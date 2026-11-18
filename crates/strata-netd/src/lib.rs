//! strata-netd: serves one client connection. It holds no ZFS rights and no secrets: the
//! handshake's CPace half runs in zfsd, and everything netd writes goes into descriptors
//! zfsd hands it, already scoped to the authenticated client.

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use strata_proto::fault;
use strata_proto::hs::{HelloResult, Hs, RejectReason, ServerHello, noise_builder, prologue, recv_hs, send_hs};
use strata_proto::local::LocalSock;
use strata_proto::msg::{AuthMode, ErrorCode, HeadRef, Msg, PROTOCOL_VERSION, RestoreMode, SourceInfo, ZFS_CHUNK};
use strata_proto::names::valid_name;
use strata_proto::session::Session;
use strata_proto::zipc::{ZReq, ZResp};
use strata_zstream::{Expect, Validator};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const COMPRESS_THREADS: usize = 2;
/// Forwarded-byte count at which the `netd.receive.midstream` fault point fires.
const MIDSTREAM: u64 = 1 << 20;

pub fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).format_timestamp(None).init();
}

struct Zfsd {
    sock: LocalSock,
}

impl Zfsd {
    fn call_fd(&self, req: &ZReq, fd: Option<&OwnedFd>) -> anyhow::Result<(ZResp, Option<OwnedFd>)> {
        let msg = req.encode()?;
        match fd {
            Some(f) => self.sock.send(&msg, &[f.as_fd()])?,
            None => self.sock.send(&msg, &[])?,
        }
        let r = self.sock.recv()?.context("zfsd closed the connection")?;
        let resp = ZResp::decode(&r.msg)?;
        let mut fds = r.fds;
        if fds.len() > 1 {
            bail!("zfsd sent more than one descriptor");
        }
        Ok((resp, fds.pop()))
    }

    fn call(&self, req: &ZReq) -> anyhow::Result<ZResp> {
        let (resp, fd) = self.call_fd(req, None)?;
        if fd.is_some() {
            bail!("unexpected descriptor from zfsd");
        }
        Ok(resp)
    }

    fn list(&self, req: &ZReq) -> anyhow::Result<Result<Vec<ZResp>, Msg>> {
        let mut out = Vec::new();
        let mut resp = self.call(req)?;
        loop {
            match resp {
                ZResp::ListEnd => return Ok(Ok(out)),
                ZResp::Error { code, message } => return Ok(Err(Msg::Error { code, message })),
                ZResp::Source { .. } | ZResp::Snapshot(_) => out.push(resp),
                other => bail!("unexpected zfsd reply in a list: {other:?}"),
            }
            let r = self.sock.recv()?.context("zfsd closed the connection")?;
            resp = ZResp::decode(&r.msg)?;
        }
    }
}

fn fail(stream: &TcpStream, reason: RejectReason) {
    let _ = send_hs(&mut &*stream, &Hs::Fail(reason));
}

fn handshake(tcp: TcpStream, z: &Zfsd) -> anyhow::Result<Option<(Session, String)>> {
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    tcp.set_nodelay(true)?;
    let mut s = &tcp;
    let (hello, hello_bytes) = recv_hs(&mut s)?;
    let Hs::Hello(h) = hello else { bail!("expected Hello") };
    let reject = |reason, retry_after_ms| -> anyhow::Result<Option<(Session, String)>> {
        let sh = ServerHello {
            version: PROTOCOL_VERSION,
            server_id: [0; 16],
            nonce: [0; 16],
            result: HelloResult::Reject { reason, retry_after_ms },
        };
        send_hs(&mut &tcp, &Hs::ServerHello(sh))?;
        Ok(None)
    };
    if !valid_name(&h.client) {
        return reject(RejectReason::UnknownClient, 0);
    }
    let (version, server_id, nonce, insecure) =
        match z.call(&ZReq::Hello { version: h.version, client: h.client.clone(), auth: h.auth, nonce: h.nonce })? {
            ZResp::HelloOk { version, server_id, nonce, insecure } => (version, server_id, nonce, insecure),
            ZResp::Reject { reason, retry_after_ms } => return reject(reason, retry_after_ms),
            other => bail!("unexpected zfsd reply to Hello: {other:?}"),
        };
    let sh = ServerHello { version, server_id, nonce, result: HelloResult::Proceed };
    let sh_bytes = send_hs(&mut s, &Hs::ServerHello(sh))?;
    if insecure {
        if h.auth != AuthMode::None {
            bail!("zfsd admitted a psk client without CPace");
        }
        return Ok(Some((Session::plain(tcp, COMPRESS_THREADS)?, h.client)));
    }
    let Hs::CpaceA { ya } = recv_hs(&mut s)?.0 else { bail!("expected CpaceA") };
    match z.call(&ZReq::CpaceA { ya })? {
        ZResp::CpaceB { yb, tb } => {
            send_hs(&mut s, &Hs::CpaceB { yb, tb })?;
        }
        ZResp::Reject { reason, .. } => {
            fail(&tcp, reason);
            return Ok(None);
        }
        other => bail!("unexpected zfsd reply to CpaceA: {other:?}"),
    }
    let Hs::Confirm { ta } = recv_hs(&mut s)?.0 else { bail!("expected Confirm") };
    let psk = match z.call(&ZReq::Confirm { ta })? {
        ZResp::Authenticated { psk } => psk,
        ZResp::Reject { reason, .. } => {
            fail(&tcp, reason);
            return Ok(None);
        }
        other => bail!("unexpected zfsd reply to Confirm: {other:?}"),
    };
    let prologue = prologue(&hello_bytes, &sh_bytes);
    let mut noise = noise_builder(&prologue, &psk).build_responder()?;
    let Hs::Noise(m1) = recv_hs(&mut s)?.0 else { bail!("expected Noise message 1") };
    let mut buf = vec![0u8; 1024];
    noise.read_message(&m1, &mut buf)?;
    let n = noise.write_message(&[], &mut buf)?;
    send_hs(&mut s, &Hs::Noise(buf[..n].to_vec()))?;
    let t = noise.into_stateless_transport_mode()?;
    Ok(Some((Session::noise(tcp, t, COMPRESS_THREADS)?, h.client)))
}

struct Receiving {
    pipe: File,
    v: Validator,
    out: Vec<u8>,
    forwarded: u64,
}

struct Backup {
    resume_toguid: Option<u64>,
    rx: Option<Receiving>,
}

fn ready(s: &mut Session, r: ZResp) -> anyhow::Result<Option<Backup>> {
    match r {
        ZResp::Ready { server_gen, head, resume } => {
            s.writer.send_now(&Msg::Ready {
                server_gen,
                head: head.map(|(name, guid)| HeadRef { name, guid }),
                resume,
            })?;
            Ok(Some(Backup { resume_toguid: resume.map(|r| r.toguid), rx: None }))
        }
        other => {
            s.writer.send_now(&zresp_to_msg(other))?;
            Ok(None)
        }
    }
}

fn zresp_to_msg(r: ZResp) -> Msg {
    match r {
        ZResp::Error { code, message } => Msg::Error { code, message },
        ZResp::Busy { retry_after_ms } => Msg::Busy { retry_after_ms },
        other => Msg::Error { code: ErrorCode::Internal, message: format!("unexpected zfsd reply {other:?}") },
    }
}

fn session(mut s: Session, z: &Zfsd, client: &str) -> anyhow::Result<()> {
    s.set_read_timeout(Some(IDLE_TIMEOUT))?;
    let mut backup: Option<Backup> = None;
    loop {
        let msg = match s.reader.recv() {
            Ok(m) => m,
            Err(strata_proto::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        match msg {
            Msg::ListSources => {
                let reply = match z.list(&ZReq::ListSources)? {
                    Ok(items) => Msg::Sources(
                        items
                            .into_iter()
                            .filter_map(|r| match r {
                                ZResp::Source { name, kind, snapshots, newest } => {
                                    Some(SourceInfo { name, kind, snapshots, newest })
                                }
                                _ => None,
                            })
                            .collect(),
                    ),
                    Err(m) => m,
                };
                s.writer.send_now(&reply)?;
            }
            Msg::ListSnapshots { source } => {
                let reply = match z.list(&ZReq::ListSnapshots { source })? {
                    Ok(items) => Msg::Snapshots(
                        items
                            .into_iter()
                            .filter_map(|r| match r {
                                ZResp::Snapshot(i) => Some(i),
                                _ => None,
                            })
                            .collect(),
                    ),
                    Err(m) => m,
                };
                s.writer.send_now(&reply)?;
            }
            Msg::BeginBackup { source, kind, .. } => {
                if backup.is_some() {
                    bail!("BeginBackup during a backup");
                }
                if !valid_name(&source) {
                    s.writer
                        .send_now(&Msg::Error { code: ErrorCode::BadRequest, message: "invalid source name".into() })?;
                    continue;
                }
                log::info!("{client}: backup of {source} requested");
                let r = z.call(&ZReq::BeginBackup { source, kind })?;
                backup = ready(&mut s, r)?;
            }
            Msg::DiscardResume => {
                if backup.as_ref().is_none_or(|b| b.rx.is_some()) {
                    bail!("DiscardResume outside a backup that hasn't started streaming");
                }
                let r = z.call(&ZReq::DiscardResume)?;
                backup = ready(&mut s, r)?;
            }
            Msg::ZfsChunk(data) => {
                let Some(b) = backup.as_mut() else { bail!("ZfsChunk outside a backup") };
                if b.rx.is_none() {
                    let (resp, fd) = z.call_fd(&ZReq::StartReceive, None)?;
                    match (resp, fd) {
                        (ZResp::ReceiveReady { expected_fromguid }, Some(fd)) => {
                            fault::point("netd.receive.started");
                            b.rx = Some(Receiving {
                                pipe: File::from(fd),
                                v: Validator::new(Expect {
                                    fromguid: expected_fromguid,
                                    toguid: b.resume_toguid,
                                    allow_raw: true,
                                }),
                                out: Vec::with_capacity(ZFS_CHUNK * 2),
                                forwarded: 0,
                            });
                        }
                        (other, _) => {
                            s.writer.send_now(&zresp_to_msg(other))?;
                            backup = None;
                            continue;
                        }
                    }
                }
                let rx = b.rx.as_mut().unwrap();
                let res =
                    rx.v.push(&data, &mut rx.out).map_err(|e| (ErrorCode::Validation, e.to_string())).and_then(|_| {
                        rx.pipe
                            .write_all(&rx.out)
                            .map_err(|e| (ErrorCode::Internal, format!("zfs receive stopped reading: {e}")))
                    });
                let before = rx.forwarded;
                rx.forwarded += rx.out.len() as u64;
                if before < MIDSTREAM && rx.forwarded >= MIDSTREAM {
                    fault::point("netd.receive.midstream");
                }
                rx.out.clear();
                if let Err((code, message)) = res {
                    log::warn!("{client}: backup stream refused: {message}");
                    // Closes the receive pipe before Abort: zfsd waits for `zfs receive` to
                    // exit, and the receive only sees EOF once this write end is gone.
                    drop(backup.take());
                    z.call(&ZReq::Abort)?;
                    s.writer.send_now(&Msg::Error { code, message })?;
                    return Ok(());
                }
            }
            Msg::Commit { generation, meta } => {
                let Some(mut b) = backup.take() else { bail!("Commit outside a backup") };
                let Some(rx) = b.rx.take() else { bail!("Commit before any stream data") };
                if let Err(e) = rx.v.finish() {
                    drop(rx);
                    z.call(&ZReq::Abort)?;
                    s.writer.send_now(&Msg::Error { code: ErrorCode::Validation, message: e.to_string() })?;
                    return Ok(());
                }
                // zfsd's Commit waits for `zfs receive` to exit, which needs EOF on this pipe.
                drop(rx.pipe);
                fault::point("netd.commit.sent");
                match z.call(&ZReq::Commit { generation, interval_secs: meta.interval_secs })? {
                    ZResp::Committed { snapshot } => {
                        log::info!("{client}: committed {snapshot}");
                        s.writer.send_now(&Msg::Committed { snapshot })?;
                    }
                    other => s.writer.send_now(&zresp_to_msg(other))?,
                }
            }
            Msg::Abort => {
                drop(backup.take());
                z.call(&ZReq::Abort)?;
                return Ok(());
            }
            Msg::Rebase { source, snapshot } => {
                if backup.is_some() {
                    bail!("Rebase during a backup");
                }
                log::info!("{client}: rebase of {source} onto {snapshot} requested");
                let reply = match z.call(&ZReq::Rebase { source, snapshot })? {
                    ZResp::Ok => Msg::Rebased,
                    other => zresp_to_msg(other),
                };
                s.writer.send_now(&reply)?;
            }
            Msg::BeginRestore { source, snapshot, mode } => {
                if backup.is_some() {
                    bail!("BeginRestore during a backup");
                }
                let from = match mode {
                    RestoreMode::Full => None,
                    RestoreMode::Delta { from } => Some(from),
                };
                log::info!("{client}: restore of {source}@{snapshot} requested");
                match z.call_fd(&ZReq::BeginRestore { source, snapshot, from }, None)? {
                    (ZResp::RestoreReady { .. }, Some(fd)) => {
                        let mut pipe = File::from(fd);
                        let mut buf = vec![0u8; ZFS_CHUNK];
                        loop {
                            let n = pipe.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            s.writer.send(&Msg::ZfsChunk(buf[..n].to_vec()))?;
                        }
                        let reply = match z.call(&ZReq::RestoreStatus)? {
                            ZResp::Ok => Msg::RestoreDone,
                            other => zresp_to_msg(other),
                        };
                        s.writer.send_now(&reply)?;
                    }
                    (other, _) => s.writer.send_now(&zresp_to_msg(other))?,
                }
            }
            other => bail!("unexpected message {other:?}"),
        }
    }
}

/// Serves one accepted connection. The TCP socket goes to zfsd before netd reads a byte
/// from it, so zfsd learns the peer address from the kernel while this process is still
/// in a state no client input has touched.
pub fn serve(tcp: TcpStream, zfsd_socket: &Path) -> anyhow::Result<()> {
    let peer = tcp.peer_addr().ok();
    let z = Zfsd {
        sock: LocalSock::connect(zfsd_socket).with_context(|| format!("connecting to {}", zfsd_socket.display()))?,
    };
    let tcp_fd = OwnedFd::from(tcp.try_clone()?);
    match z.call_fd(&ZReq::Connect, Some(&tcp_fd))?.0 {
        ZResp::Ok => {}
        other => bail!("zfsd refused the connection: {other:?}"),
    }
    drop(tcp_fd);
    let Some((sess, client)) = handshake(tcp, &z)? else {
        log::info!("{peer:?}: handshake rejected");
        return Ok(());
    };
    session(sess, &z, &client)
}
