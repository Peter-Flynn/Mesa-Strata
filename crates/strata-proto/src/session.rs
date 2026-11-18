//! Post-handshake transport.
//!
//! Layers, bottom up:
//! - frames: `u16 BE length || payload`, payload ≤ 65535 bytes; under Noise each payload is
//!   one AES-GCM ciphertext of at most 65519 plaintext bytes, with per-direction nonces
//!   counting from 0. Frame boundaries carry no meaning above this layer.
//! - batches, on the decrypted byte stream: `kind u8 (0 raw, 1 zstd) || raw_len u32 LE ||
//!   enc_len u32 LE || enc_len bytes`.
//! - messages, inside a batch's raw bytes: `len u32 LE || postcard(Msg)`. A message never
//!   spans two batches.
//!
//! The writer fills ~1 MiB batches, compresses them on a worker pool in parallel and writes
//! them in order from one writer thread. The zstd level adapts: every 8 batches the writer
//! thread compares the time it spent writing to the socket with the time it spent waiting
//! for compressed batches, and moves the level up (network-bound) or down (CPU-bound)
//! between 1 and 9. A batch that compresses by less than 3% is sent raw, and the next 64
//! batches are sent raw without trying.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::TcpStream;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::frame::{MAX_PLAINTEXT, read_frame, write_frame};
use crate::msg::{self, MAX_MSG, Msg};
use crate::{Error, Result};

pub const BATCH_TARGET: usize = 1 << 20;
pub const MAX_BATCH_RAW: usize = BATCH_TARGET + MAX_MSG + 64;
const BATCH_HEADER: usize = 9;
/// Batches below this size are control traffic and always go raw.
const MIN_COMPRESS: usize = 4096;
const RAW_PAUSE_BATCHES: u64 = 64;
const ADAPT_EVERY: u32 = 8;
const MIN_LEVEL: i32 = 1;
const MAX_LEVEL: i32 = 9;
const START_LEVEL: i32 = 3;
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_PROBES: u32 = 6;

#[derive(Clone)]
enum Cipher {
    Plain,
    Noise(Arc<snow::StatelessTransportState>),
}

struct FrameWriter {
    stream: TcpStream,
    cipher: Cipher,
    nonce: u64,
    pending: Vec<u8>,
    ct: Vec<u8>,
}

impl FrameWriter {
    fn put(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let room = MAX_PLAINTEXT - self.pending.len();
            let n = room.min(data.len());
            self.pending.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.pending.len() == MAX_PLAINTEXT {
                self.emit()?;
            }
        }
        Ok(())
    }

    fn emit(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        match &self.cipher {
            Cipher::Plain => write_frame(&mut self.stream, &self.pending)?,
            Cipher::Noise(t) => {
                self.ct.resize(self.pending.len() + crate::frame::AEAD_TAG, 0);
                let n = t
                    .write_message(self.nonce, &self.pending, &mut self.ct)
                    .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
                self.nonce += 1;
                write_frame(&mut self.stream, &self.ct[..n])?;
            }
        }
        self.pending.clear();
        Ok(())
    }
}

struct FrameReader {
    stream: Box<dyn Read + Send>,
    cipher: Cipher,
    nonce: u64,
    plain: Vec<u8>,
    pos: usize,
    frame: Vec<u8>,
}

impl Read for FrameReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.plain.len() {
            read_frame(&mut self.stream, &mut self.frame)?;
            match &self.cipher {
                Cipher::Plain => std::mem::swap(&mut self.plain, &mut self.frame),
                Cipher::Noise(t) => {
                    self.plain.resize(self.frame.len(), 0);
                    let n = t
                        .read_message(self.nonce, &self.frame, &mut self.plain)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("noise decrypt: {e}")))?;
                    self.nonce += 1;
                    self.plain.truncate(n);
                }
            }
            self.pos = 0;
        }
        let n = out.len().min(self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

struct WState {
    written: u64,
    error: Option<String>,
}

struct WShared {
    state: Mutex<WState>,
    cv: Condvar,
    level: AtomicI32,
    raw_until: AtomicU64,
}

struct Job {
    seq: u64,
    raw: Vec<u8>,
}

pub struct MsgWriter {
    batch: Vec<u8>,
    next_seq: u64,
    max_inflight: u64,
    shared: Arc<WShared>,
    jobs: Option<SyncSender<Job>>,
    threads: Vec<JoinHandle<()>>,
}

fn encode_batch(job: &Job, shared: &WShared) -> Vec<u8> {
    let raw = &job.raw;
    let try_compress = raw.len() >= MIN_COMPRESS && job.seq >= shared.raw_until.load(Ordering::Relaxed);
    let compressed = if try_compress {
        let level = shared.level.load(Ordering::Relaxed);
        zstd::bulk::compress(raw, level)
            .ok()
            .filter(|c| c.len() < raw.len() - raw.len() * 3 / 100)
    } else {
        None
    };
    if try_compress && compressed.is_none() {
        shared.raw_until.fetch_max(job.seq + 1 + RAW_PAUSE_BATCHES, Ordering::Relaxed);
    }
    let (kind, body): (u8, &[u8]) = match &compressed {
        Some(c) => (1, c),
        None => (0, raw),
    };
    let mut out = Vec::with_capacity(BATCH_HEADER + body.len());
    out.push(kind);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn writer_thread(mut fw: FrameWriter, results: Receiver<(u64, Vec<u8>, bool)>, shared: Arc<WShared>) {
    let mut pending: BTreeMap<u64, (Vec<u8>, bool)> = BTreeMap::new();
    let mut next = 0u64;
    let (mut waited, mut writing) = (Duration::ZERO, Duration::ZERO);
    let mut counted = 0u32;
    loop {
        while let Some((data, big)) = pending.remove(&next) {
            let t = Instant::now();
            let r = fw.put(&data).and_then(|_| fw.emit());
            if big {
                writing += t.elapsed();
                counted += 1;
            }
            let mut st = shared.state.lock().unwrap();
            if let Err(e) = r {
                st.error.get_or_insert(format!("send failed: {e}"));
                shared.cv.notify_all();
                return;
            }
            next += 1;
            st.written = next;
            shared.cv.notify_all();
            drop(st);
            if counted >= ADAPT_EVERY {
                let l = shared.level.load(Ordering::Relaxed);
                let nl = if writing > waited { (l + 1).min(MAX_LEVEL) } else { (l - 1).max(MIN_LEVEL) };
                shared.level.store(nl, Ordering::Relaxed);
                (waited, writing, counted) = (Duration::ZERO, Duration::ZERO, 0);
            }
        }
        let t = Instant::now();
        match results.recv() {
            Ok((seq, data, big)) => {
                if big {
                    waited += t.elapsed();
                }
                pending.insert(seq, (data, big));
            }
            Err(_) => return,
        }
    }
}

impl MsgWriter {
    fn new(fw: FrameWriter, threads: usize) -> MsgWriter {
        let threads = threads.max(1);
        let shared = Arc::new(WShared {
            state: Mutex::new(WState { written: 0, error: None }),
            cv: Condvar::new(),
            level: AtomicI32::new(START_LEVEL),
            raw_until: AtomicU64::new(0),
        });
        let (job_tx, job_rx) = mpsc::sync_channel::<Job>(threads * 2);
        let job_rx = Arc::new(Mutex::new(job_rx));
        let (res_tx, res_rx) = mpsc::channel();
        let mut handles = Vec::new();
        for _ in 0..threads {
            let rx = job_rx.clone();
            let tx = res_tx.clone();
            let sh = shared.clone();
            handles.push(std::thread::spawn(move || {
                loop {
                    let job = match rx.lock().unwrap().recv() {
                        Ok(j) => j,
                        Err(_) => return,
                    };
                    let big = job.raw.len() >= MIN_COMPRESS;
                    let enc = encode_batch(&job, &sh);
                    if tx.send((job.seq, enc, big)).is_err() {
                        return;
                    }
                }
            }));
        }
        drop(res_tx);
        let sh = shared.clone();
        handles.push(std::thread::spawn(move || writer_thread(fw, res_rx, sh)));
        MsgWriter {
            batch: Vec::with_capacity(BATCH_TARGET + 1024),
            next_seq: 0,
            max_inflight: threads as u64 * 2 + 2,
            shared,
            jobs: Some(job_tx),
            threads: handles,
        }
    }

    fn check(&self) -> Result<()> {
        match &self.shared.state.lock().unwrap().error {
            Some(e) => Err(Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, e.clone()))),
            None => Ok(()),
        }
    }

    fn submit(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        {
            let mut st = self.shared.state.lock().unwrap();
            while st.error.is_none() && self.next_seq - st.written >= self.max_inflight {
                st = self.shared.cv.wait(st).unwrap();
            }
        }
        self.check()?;
        let raw = std::mem::replace(&mut self.batch, Vec::with_capacity(BATCH_TARGET + 1024));
        let job = Job { seq: self.next_seq, raw };
        self.next_seq += 1;
        self.jobs
            .as_ref()
            .expect("writer finished")
            .send(job)
            .map_err(|_| Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "writer stopped")))
    }

    /// Queues a message; large batches go out without waiting for the socket.
    pub fn send(&mut self, m: &Msg) -> Result<()> {
        self.check()?;
        msg::encode(m, &mut self.batch);
        if self.batch.len() >= BATCH_TARGET {
            self.submit()?;
        }
        Ok(())
    }

    /// Sends everything queued and waits until it has been written to the socket.
    pub fn flush(&mut self) -> Result<()> {
        self.submit()?;
        let mut st = self.shared.state.lock().unwrap();
        while st.error.is_none() && st.written < self.next_seq {
            st = self.shared.cv.wait(st).unwrap();
        }
        drop(st);
        self.check()
    }

    pub fn send_now(&mut self, m: &Msg) -> Result<()> {
        self.send(m)?;
        self.flush()
    }

    pub fn level(&self) -> i32 {
        self.shared.level.load(Ordering::Relaxed)
    }
}

impl Drop for MsgWriter {
    fn drop(&mut self) {
        self.jobs.take();
        for h in self.threads.drain(..) {
            let _ = h.join();
        }
    }
}

pub struct MsgReader {
    fr: FrameReader,
    batch: Vec<u8>,
    enc: Vec<u8>,
    pos: usize,
}

impl MsgReader {
    /// A reader over plaintext frames from any byte source (fuzzing, tests).
    pub fn plain(r: impl Read + Send + 'static) -> MsgReader {
        let fr = FrameReader { stream: Box::new(r), cipher: Cipher::Plain, nonce: 0, plain: Vec::new(), pos: 0, frame: Vec::new() };
        MsgReader { fr, batch: Vec::new(), enc: Vec::new(), pos: 0 }
    }

    fn read_batch(&mut self) -> Result<()> {
        let mut hdr = [0u8; BATCH_HEADER];
        self.fr.read_exact(&mut hdr)?;
        let kind = hdr[0];
        let raw_len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
        let enc_len = u32::from_le_bytes(hdr[5..9].try_into().unwrap()) as usize;
        if raw_len > MAX_BATCH_RAW || enc_len > raw_len || raw_len == 0 {
            return Err(Error::Protocol(format!("bad batch header: raw {raw_len}, encoded {enc_len}")));
        }
        self.enc.resize(enc_len, 0);
        self.fr.read_exact(&mut self.enc)?;
        match kind {
            0 if enc_len == raw_len => std::mem::swap(&mut self.batch, &mut self.enc),
            1 => {
                self.batch.clear();
                self.batch.resize(raw_len, 0);
                let n = zstd::bulk::Decompressor::new()
                    .and_then(|mut d| d.decompress_to_buffer(&self.enc, &mut self.batch[..]))
                    .map_err(|e| Error::Protocol(format!("zstd: {e}")))?;
                if n != raw_len {
                    return Err(Error::Protocol("batch decompressed to the wrong length".into()));
                }
            }
            _ => return Err(Error::Protocol(format!("bad batch kind {kind}"))),
        }
        self.pos = 0;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Msg> {
        if self.pos == self.batch.len() {
            self.read_batch()?;
        }
        let rest = &self.batch[self.pos..];
        if rest.len() < 4 {
            return Err(Error::Protocol("truncated message length".into()));
        }
        let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        if len > MAX_MSG || len > rest.len() - 4 {
            return Err(Error::Protocol(format!("bad message length {len}")));
        }
        let m = msg::decode(&rest[4..4 + len]).map_err(|e| Error::Protocol(format!("bad message: {e}")))?;
        self.pos += 4 + len;
        Ok(m)
    }

    /// Receives a message, turning a remote `Error` into `Err`.
    pub fn expect(&mut self) -> Result<Msg> {
        match self.recv()? {
            Msg::Error { code, message } => Err(Error::Remote { code, message }),
            m => Ok(m),
        }
    }
}

pub struct Session {
    pub reader: MsgReader,
    pub writer: MsgWriter,
    stream: TcpStream,
}

impl Session {
    fn build(stream: TcpStream, cipher: Cipher, threads: usize) -> io::Result<Session> {
        // A peer that loses power leaves the connection half-open; keepalive probes end it
        // within KEEPALIVE_IDLE + KEEPALIVE_INTERVAL * KEEPALIVE_PROBES (2 minutes), which
        // frees the server's per-source session for the peer's next run.
        use rustix::net::sockopt;
        sockopt::set_socket_keepalive(&stream, true).ok();
        sockopt::set_tcp_keepidle(&stream, KEEPALIVE_IDLE).ok();
        sockopt::set_tcp_keepintvl(&stream, KEEPALIVE_INTERVAL).ok();
        sockopt::set_tcp_keepcnt(&stream, KEEPALIVE_PROBES).ok();
        let fw = FrameWriter {
            stream: stream.try_clone()?,
            cipher: cipher.clone(),
            nonce: 0,
            pending: Vec::with_capacity(MAX_PLAINTEXT),
            ct: Vec::new(),
        };
        let fr = FrameReader {
            stream: Box::new(stream.try_clone()?),
            cipher,
            nonce: 0,
            plain: Vec::new(),
            pos: 0,
            frame: Vec::new(),
        };
        Ok(Session {
            reader: MsgReader { fr, batch: Vec::new(), enc: Vec::new(), pos: 0 },
            writer: MsgWriter::new(fw, threads),
            stream,
        })
    }

    pub fn plain(stream: TcpStream, threads: usize) -> io::Result<Session> {
        Self::build(stream, Cipher::Plain, threads)
    }

    pub fn noise(stream: TcpStream, t: snow::StatelessTransportState, threads: usize) -> io::Result<Session> {
        Self::build(stream, Cipher::Noise(Arc::new(t)), threads)
    }

    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(t)
    }

    pub fn close(mut self) -> Result<()> {
        self.writer.flush()?;
        self.stream.shutdown(std::net::Shutdown::Write).ok();
        Ok(())
    }

    pub fn call(&mut self, msg: &Msg) -> Result<Msg> {
        self.writer.send_now(msg)?;
        self.reader.expect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    fn noise_pair() -> (snow::StatelessTransportState, snow::StatelessTransportState) {
        let psk = [7u8; 32];
        let mut i = crate::hs::noise_builder(b"p", &psk).build_initiator().unwrap();
        let mut r = crate::hs::noise_builder(b"p", &psk).build_responder().unwrap();
        let (mut m, mut p) = (vec![0u8; 1024], vec![0u8; 1024]);
        let n = i.write_message(&[], &mut m).unwrap();
        r.read_message(&m[..n], &mut p).unwrap();
        let n = r.write_message(&[], &mut m).unwrap();
        i.read_message(&m[..n], &mut p).unwrap();
        (i.into_stateless_transport_mode().unwrap(), r.into_stateless_transport_mode().unwrap())
    }

    fn exchange(mut a: Session, mut b: Session) {
        let mut sent = Vec::new();
        for i in 0..200u32 {
            let data: Vec<u8> = if i % 3 == 0 {
                (0..msg::ZFS_CHUNK).map(|x| (x % 7) as u8).collect()
            } else {
                (0..40_000u32).map(|x| (x.wrapping_mul(2_654_435_761) >> 13) as u8 ^ i as u8).collect()
            };
            sent.push(data);
        }
        let s2 = sent.clone();
        let t = std::thread::spawn(move || {
            for d in s2 {
                a.writer.send(&Msg::ZfsChunk(d)).unwrap();
            }
            a.writer.send(&Msg::Checkpoint).unwrap();
            a.close().unwrap();
        });
        for d in sent {
            assert_eq!(b.reader.recv().unwrap(), Msg::ZfsChunk(d));
        }
        assert_eq!(b.reader.recv().unwrap(), Msg::Checkpoint);
        assert!(b.reader.recv().is_err());
        t.join().unwrap();
    }

    #[test]
    fn plain_roundtrip() {
        let (a, b) = pair();
        exchange(Session::plain(a, 3).unwrap(), Session::plain(b, 1).unwrap());
    }

    #[test]
    fn noise_roundtrip() {
        let (a, b) = pair();
        let (ti, tr) = noise_pair();
        exchange(Session::noise(a, ti, 2).unwrap(), Session::noise(b, tr, 1).unwrap());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (a, b) = pair();
        let (ti, tr) = noise_pair();
        let mut raw = a.try_clone().unwrap();
        let mut sb = Session::noise(b, tr, 1).unwrap();
        let t = ti;
        let mut ct = vec![0u8; 100];
        let n = t.write_message(0, b"hello world, this is a batch", &mut ct).unwrap();
        ct[5] ^= 1;
        write_frame(&mut raw, &ct[..n]).unwrap();
        assert!(sb.reader.recv().is_err());
    }

    #[test]
    fn incompressible_batches_pause_compression() {
        let shared = WShared {
            state: Mutex::new(WState { written: 0, error: None }),
            cv: Condvar::new(),
            level: AtomicI32::new(3),
            raw_until: AtomicU64::new(0),
        };
        let mut noise = vec![0u8; 100_000];
        getrandom::fill(&mut noise).unwrap();
        let out = encode_batch(&Job { seq: 5, raw: noise }, &shared);
        assert_eq!(out[0], 0);
        assert_eq!(shared.raw_until.load(Ordering::Relaxed), 5 + 1 + RAW_PAUSE_BATCHES);
        let zeros = encode_batch(&Job { seq: 10, raw: vec![0u8; 100_000] }, &shared);
        assert_eq!(zeros[0], 0, "paused batches go raw");
        let zeros = encode_batch(&Job { seq: 70, raw: vec![0u8; 100_000] }, &shared);
        assert_eq!(zeros[0], 1, "compression probes again after the pause");
    }
}
