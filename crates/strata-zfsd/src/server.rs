//! zfsd's connection handler. One thread per netd connection; each connection moves through
//!
//! ```text
//! Start --Connect(tcp fd)--> Connected --Hello--> Authenticated            (auth none)
//!                                         \--> Hello(psk) --CpaceA--> Cpace --Confirm--> Authenticated
//! ```
//!
//! and only an authenticated connection may list, back up or restore, always within its
//! own client's `<pool>/strata/<client>/ds` tree. A connection holds at most one backup or
//! restore session at a time; dropping the connection aborts it.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use strata_proto::cpace::{self, Keys};
use strata_proto::fault;
use strata_proto::hs::{AD_CLIENT, AD_SERVER, PSK_LABEL, RejectReason, channel_id, random16, session_id};
use strata_proto::kdf::{DerivedKey, ServerId};
use strata_proto::local::{LocalListener, LocalSock};
use strata_proto::msg::{AuthMode, ErrorCode, ResumePoint, SUPPORTED_VERSIONS, SourceKind};
use strata_proto::names::{server_snapshot_name, valid_name};
use strata_proto::zipc::{ZReq, ZResp};
use strata_zfs::{Job, RecvOpts, SendFlags, Zfs};

use crate::auth::{Backoff, Key, peer_of};
use crate::config::ServerConfig;
use crate::ops::{finalize_head, kind_matches, kind_of, now, prune, snapshot_info, source_state, strata_snaps};

const BUSY_RETRY_MS: u32 = 30_000;

pub struct Server {
    pub cfg: ServerConfig,
    pub zfs: Arc<dyn Zfs>,
    pub keys: BTreeMap<String, DerivedKey>,
    pub server_id: ServerId,
    slots: Mutex<HashSet<(String, String)>>,
    backoff: Mutex<Backoff>,
}

struct Slot {
    srv: Arc<Server>,
    key: (String, String),
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.srv.slots.lock().unwrap().remove(&self.key);
    }
}

impl Server {
    pub fn new(cfg: ServerConfig, zfs: Arc<dyn Zfs>, keys: BTreeMap<String, DerivedKey>, server_id: ServerId) -> Arc<Server> {
        Arc::new(Server { cfg, zfs, keys, server_id, slots: Mutex::new(HashSet::new()), backoff: Mutex::new(Backoff::default()) })
    }

    fn acquire(self: &Arc<Server>, client: &str, source: &str) -> Option<Slot> {
        let key = (client.to_string(), source.to_string());
        let mut s = self.slots.lock().unwrap();
        if s.contains(&key) || s.len() >= self.cfg.max_sessions {
            return None;
        }
        s.insert(key.clone());
        Some(Slot { srv: self.clone(), key })
    }
}

pub fn serve(srv: Arc<Server>, listener: LocalListener) -> anyhow::Result<()> {
    loop {
        let sock = listener.accept()?;
        let srv = srv.clone();
        std::thread::spawn(move || {
            let mut c = Conn::new(srv, sock);
            if let Err(e) = c.run() {
                log::warn!("connection ended: {e}");
            }
            c.cleanup();
        });
    }
}

struct PendingHello {
    client: String,
    nonce_c: [u8; 16],
    nonce_s: [u8; 16],
}

struct Backup {
    _slot: Slot,
    source: String,
    ds: String,
    generation: u64,
    head_guid: u64,
    resume: Option<ResumePoint>,
    recv: Option<(Job, String)>,
}

struct Restore {
    _slot: Slot,
    job: Job,
}

struct Conn {
    srv: Arc<Server>,
    sock: LocalSock,
    peer: Option<IpAddr>,
    hello: Option<PendingHello>,
    cpace: Option<(Keys, [u8; 32])>,
    client: Option<String>,
    backup: Option<Backup>,
    restore: Option<Restore>,
}

type Reply = Vec<(ZResp, Option<OwnedFd>)>;

fn one(r: ZResp) -> Result<Reply, String> {
    Ok(vec![(r, None)])
}

fn err(code: ErrorCode, msg: impl Into<String>) -> Result<Reply, String> {
    one(ZResp::error(code, msg))
}

impl Conn {
    fn new(srv: Arc<Server>, sock: LocalSock) -> Conn {
        Conn { srv, sock, peer: None, hello: None, cpace: None, client: None, backup: None, restore: None }
    }

    fn run(&mut self) -> anyhow::Result<()> {
        while let Some(rcv) = self.sock.recv()? {
            let req = ZReq::decode(&rcv.msg)?;
            let replies = match self.handle(req, rcv.fds) {
                Ok(r) => r,
                Err(fatal) => {
                    let _ = self.send(ZResp::error(ErrorCode::BadRequest, fatal.clone()), None);
                    anyhow::bail!("protocol violation: {fatal}");
                }
            };
            for (resp, fd) in replies {
                self.send(resp, fd)?;
            }
        }
        Ok(())
    }

    fn send(&self, resp: ZResp, fd: Option<OwnedFd>) -> anyhow::Result<()> {
        let msg = resp.encode()?;
        match &fd {
            Some(f) => self.sock.send(&msg, &[f.as_fd()])?,
            None => self.sock.send(&msg, &[])?,
        }
        Ok(())
    }

    fn cleanup(&mut self) {
        if let Some(mut b) = self.backup.take()
            && let Some((mut job, snap)) = b.recv.take()
        {
            job.kill();
            let _ = job.wait();
            log::info!("{}: backup into {}@{snap} abandoned", b.source, b.ds);
        }
        if let Some(r) = self.restore.take() {
            let _ = r.job.wait();
        }
    }

    fn authed(&self) -> Result<&str, String> {
        self.client.as_deref().ok_or_else(|| "not authenticated".to_string())
    }

    fn reject(&self, reason: RejectReason, retry_after_ms: u32) -> Result<Reply, String> {
        one(ZResp::Reject { reason, retry_after_ms })
    }

    fn handle(&mut self, req: ZReq, mut fds: Vec<OwnedFd>) -> Result<Reply, String> {
        let expects_fd = matches!(req, ZReq::Connect);
        if !expects_fd && !fds.is_empty() {
            return Err("unexpected descriptor".into());
        }
        if self.peer.is_none() && !expects_fd {
            return Err("Connect must come first".into());
        }
        match req {
            ZReq::Connect => {
                if self.peer.is_some() || fds.len() != 1 {
                    return Err("Connect needs exactly one socket, once".into());
                }
                let fd = fds.pop().unwrap();
                self.peer = Some(peer_of(&fd, self.srv.cfg.listen_port)?);
                one(ZResp::Ok)
            }
            ZReq::Hello { version, client, auth, nonce } => self.hello(version, client, auth, nonce),
            ZReq::CpaceA { ya } => self.cpace_a(ya),
            ZReq::Confirm { ta } => self.confirm(ta),
            ZReq::ListSources => self.list_sources(),
            ZReq::ListSnapshots { source } => self.list_snapshots(&source),
            ZReq::BeginBackup { source, kind } => self.begin_backup(source, kind),
            ZReq::DiscardResume => self.discard_resume(),
            ZReq::StartReceive => self.start_receive(),
            ZReq::Commit { generation, interval_secs } => self.commit(generation, interval_secs),
            ZReq::Abort => {
                self.cleanup();
                one(ZResp::Ok)
            }
            ZReq::BeginRestore { source, snapshot, from } => self.begin_restore(&source, &snapshot, from.as_deref()),
            ZReq::RestoreStatus => {
                let r = self.restore.take().ok_or("no restore running")?;
                match r.job.wait() {
                    Ok(()) => one(ZResp::Ok),
                    Err(e) => err(ErrorCode::Internal, format!("send failed: {e}")),
                }
            }
        }
    }

    fn hello(&mut self, version: u16, client: String, auth: AuthMode, nonce_c: [u8; 16]) -> Result<Reply, String> {
        if self.client.is_some() || self.hello.is_some() {
            return Err("Hello sent twice".into());
        }
        if !SUPPORTED_VERSIONS.contains(&version) {
            return self.reject(RejectReason::UnsupportedVersion, 0);
        }
        let peer = self.peer.unwrap();
        let Some(ccfg) = self.srv.cfg.clients.get(&client).filter(|_| valid_name(&client)) else {
            log::warn!("{peer}: unknown client {client:?}");
            return self.reject(RejectReason::UnknownClient, 0);
        };
        {
            let b = self.srv.backoff.lock().unwrap();
            let now = Instant::now();
            let wait = [Key::Client(client.clone()), Key::Addr(peer)].iter().filter_map(|k| b.wait(k, now)).max();
            if let Some(w) = wait {
                return self.reject(RejectReason::BackingOff, w.as_millis().min(u32::MAX as u128) as u32);
            }
        }
        let insecure = ccfg.insecure;
        if insecure != (auth == AuthMode::None) {
            log::warn!("{peer}: client {client} asked for {auth:?}, configured insecure={insecure}");
            return self.reject(RejectReason::AuthModeMismatch, 0);
        }
        let nonce_s = random16();
        let version = version.min(*SUPPORTED_VERSIONS.iter().max().unwrap());
        if insecure {
            if !crate::config::allowed(&ccfg.allow_from, peer) {
                log::warn!("{peer}: insecure client {client} not allowed from this address");
                return self.reject(RejectReason::AddressNotAllowed, 0);
            }
            log::info!("{peer}: client {client} connected without authentication (insecure)");
            self.client = Some(client);
            return one(ZResp::HelloOk { version, server_id: self.srv.server_id, nonce: nonce_s, authenticated: true });
        }
        if !self.srv.keys.contains_key(&client) {
            return self.reject(RejectReason::Internal, 0);
        }
        self.hello = Some(PendingHello { client, nonce_c, nonce_s });
        one(ZResp::HelloOk { version, server_id: self.srv.server_id, nonce: nonce_s, authenticated: false })
    }

    fn cpace_a(&mut self, ya: [u8; 32]) -> Result<Reply, String> {
        if self.cpace.is_some() {
            return Err("CpaceA sent twice".into());
        }
        let h = self.hello.as_ref().ok_or("CpaceA before Hello")?;
        let peer = self.peer.unwrap();
        {
            // Counted as a failure until Confirm succeeds, so a guesser that hangs up
            // after seeing Tb still pays the backoff.
            let mut b = self.srv.backoff.lock().unwrap();
            let now = Instant::now();
            b.fail(Key::Client(h.client.clone()), now);
            b.fail(Key::Addr(peer), now);
        }
        let prs = self.srv.keys[&h.client];
        let ci = channel_id(&h.client, &self.srv.server_id);
        let sid = session_id(&h.nonce_c, &h.nonce_s);
        match cpace::respond(&prs, &ci, &sid, &ya, AD_CLIENT, AD_SERVER) {
            Ok((yb, keys)) => {
                let tb = keys.tag(&yb, AD_SERVER);
                self.cpace = Some((keys, ya));
                one(ZResp::CpaceB { yb, tb })
            }
            Err(_) => self.reject(RejectReason::AuthFailed, 0),
        }
    }

    fn confirm(&mut self, ta: [u8; 64]) -> Result<Reply, String> {
        let (keys, ya) = self.cpace.take().ok_or("Confirm before CpaceA")?;
        let h = self.hello.take().ok_or("Confirm before Hello")?;
        let peer = self.peer.unwrap();
        if keys.verify(&ya, AD_CLIENT, &ta).is_err() {
            log::warn!("{peer}: client {} failed authentication", h.client);
            return self.reject(RejectReason::AuthFailed, 0);
        }
        {
            let mut b = self.srv.backoff.lock().unwrap();
            b.succeed(&Key::Client(h.client.clone()));
            b.succeed(&Key::Addr(peer));
        }
        log::info!("{peer}: client {} authenticated", h.client);
        let psk = keys.derive(PSK_LABEL);
        self.client = Some(h.client);
        one(ZResp::Authenticated { psk })
    }

    fn source_ds(&self, source: &str) -> Result<String, String> {
        let client = self.authed()?;
        if !valid_name(source) {
            return Err(format!("invalid source name {source:?}"));
        }
        Ok(self.srv.cfg.source_ds(client, source))
    }

    fn list_sources(&self) -> Result<Reply, String> {
        let client = self.authed()?;
        let zfs = &*self.srv.zfs;
        let parent = self.srv.cfg.client_ds(client);
        let mut out = Vec::new();
        let children = match zfs.exists(&parent) {
            Ok(true) => zfs.children(&parent).map_err(|e| e.to_string()),
            Ok(false) => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        };
        let children = match children {
            Ok(c) => c,
            Err(e) => return err(ErrorCode::Internal, e),
        };
        for ds in children {
            let name = ds.rsplit('/').next().unwrap_or_default().to_string();
            if !valid_name(&name) {
                continue;
            }
            let (Ok(t), Ok(snaps)) = (zfs.dataset_type(&ds), strata_snaps(zfs, &ds)) else { continue };
            out.push((
                ZResp::Source {
                    name,
                    kind: kind_of(t),
                    snapshots: snaps.len() as u32,
                    newest: snaps.last().map(snapshot_info),
                },
                None,
            ));
        }
        out.push((ZResp::ListEnd, None));
        Ok(out)
    }

    fn list_snapshots(&self, source: &str) -> Result<Reply, String> {
        let ds = self.source_ds(source)?;
        let zfs = &*self.srv.zfs;
        match zfs.exists(&ds) {
            Ok(true) => {}
            Ok(false) => return err(ErrorCode::NotFound, format!("no source {source}")),
            Err(e) => return err(ErrorCode::Internal, e.to_string()),
        }
        let snaps = match strata_snaps(zfs, &ds) {
            Ok(s) => s,
            Err(e) => return err(ErrorCode::Internal, e.to_string()),
        };
        let mut out: Reply = snaps.iter().map(|s| (ZResp::Snapshot(snapshot_info(s)), None)).collect();
        out.push((ZResp::ListEnd, None));
        Ok(out)
    }

    fn ready(&mut self) -> Result<Reply, String> {
        let b = self.backup.as_mut().unwrap();
        let zfs = &*self.srv.zfs;
        let st = match source_state(zfs, &b.ds) {
            Ok(s) => s,
            Err(e) => {
                self.backup = None;
                return err(ErrorCode::Internal, e.to_string());
            }
        };
        if let Err(e) = finalize_head(zfs, &b.ds, &st.snaps) {
            log::warn!("{}: repairing holds: {e}", b.ds);
        }
        b.generation = st.generation;
        b.head_guid = st.head().map_or(0, |h| h.guid);
        b.resume = st.resume;
        one(ZResp::Ready {
            server_gen: st.generation,
            head: st.head().map(|h| (h.name.clone(), h.guid)),
            resume: st.resume,
        })
    }

    fn begin_backup(&mut self, source: String, kind: SourceKind) -> Result<Reply, String> {
        let ds = self.source_ds(&source)?;
        if self.backup.is_some() || self.restore.is_some() {
            return Err("a session is already open".into());
        }
        let client = self.client.clone().unwrap();
        let zfs = &*self.srv.zfs;
        match zfs.exists(&self.srv.cfg.client_ds(&client)) {
            Ok(true) => {}
            Ok(false) => return err(ErrorCode::NotFound, format!("no dataset tree for client {client}; strata-init creates it")),
            Err(e) => return err(ErrorCode::Internal, e.to_string()),
        }
        if let Ok(true) = zfs.exists(&ds)
            && let Ok(t) = zfs.dataset_type(&ds)
            && !kind_matches(kind, t)
        {
            return err(ErrorCode::Conflict, format!("source {source} is stored as a {t:?}, not a {kind:?}"));
        }
        let Some(slot) = self.srv.acquire(&client, &source) else {
            return one(ZResp::Busy { retry_after_ms: BUSY_RETRY_MS });
        };
        fault::point("zfsd.begin");
        self.backup = Some(Backup { _slot: slot, source, ds, generation: 0, head_guid: 0, resume: None, recv: None });
        self.ready()
    }

    fn discard_resume(&mut self) -> Result<Reply, String> {
        let b = self.backup.as_ref().ok_or("no backup session")?;
        if b.recv.is_some() {
            return Err("receive already started".into());
        }
        if b.resume.is_some()
            && let Err(e) = self.srv.zfs.receive_abort(&b.ds)
        {
            return err(ErrorCode::Internal, e.to_string());
        }
        self.ready()
    }

    fn start_receive(&mut self) -> Result<Reply, String> {
        let b = self.backup.as_mut().ok_or("no backup session")?;
        if b.recv.is_some() {
            return Err("receive already started".into());
        }
        let snap = server_snapshot_name(now(), b.generation + 1);
        let expected_fromguid = b.resume.map_or(b.head_guid, |r| r.fromguid);
        let opts = RecvOpts {
            resumable: true,
            no_mount: true,
            props: vec![("readonly".into(), "on".into())],
            origin: None,
        };
        let rx = match self.srv.zfs.receive(&format!("{}@{snap}", b.ds), &opts) {
            Ok(r) => r,
            Err(e) => return err(ErrorCode::Internal, e.to_string()),
        };
        fault::point("zfsd.receive.started");
        b.recv = Some((rx.job, snap));
        // zfsd keeps no copy of the write end: once netd closes it, `zfs receive` sees EOF.
        Ok(vec![(ZResp::ReceiveReady { expected_fromguid }, Some(rx.stdin))])
    }

    fn commit(&mut self, generation: u64, interval: Option<u64>) -> Result<Reply, String> {
        let mut b = self.backup.take().ok_or("no backup session")?;
        let (job, snap) = b.recv.take().ok_or("nothing was received")?;
        if let Err(e) = job.wait() {
            log::warn!("{}: receive failed: {e}", b.ds);
            return err(ErrorCode::Validation, format!("zfs receive failed: {e}"));
        }
        fault::point("zfsd.commit.received");
        if generation != b.generation + 1 {
            log::warn!("{}: client committed generation {generation}, server assigned {}", b.ds, b.generation + 1);
        }
        let zfs = &*self.srv.zfs;
        let full = format!("{}@{snap}", b.ds);
        let gen_s = (b.generation + 1).to_string();
        let time_s = now().to_string();
        let interval_s = interval.map(|i| i.to_string());
        let mut props = vec![("strata:gen", gen_s.as_str()), ("strata:time", time_s.as_str()), ("strata:source", b.source.as_str())];
        if let Some(i) = &interval_s {
            props.push(("strata:interval", i));
        }
        if let Err(e) = zfs.set_props(&full, &props) {
            log::warn!("{full}: setting properties: {e}");
        }
        fault::point("zfsd.commit.props");
        let snaps = match strata_snaps(zfs, &b.ds) {
            Ok(s) => s,
            Err(e) => return err(ErrorCode::Internal, e.to_string()),
        };
        if let Err(e) = finalize_head(zfs, &b.ds, &snaps) {
            log::warn!("{}: holds: {e}", b.ds);
        }
        fault::point("zfsd.commit.held");
        let client = self.client.clone().unwrap();
        match prune(zfs, &b.ds, self.srv.cfg.retention(&client), now()) {
            Ok(gone) if !gone.is_empty() => log::info!("{}: retention destroyed {}", b.ds, gone.join(" ")),
            Ok(_) => {}
            Err(e) => log::warn!("{}: retention: {e}", b.ds),
        }
        fault::point("zfsd.commit.pruned");
        log::info!("{full}: committed");
        one(ZResp::Committed { snapshot: snap })
    }

    fn begin_restore(&mut self, source: &str, snapshot: &str, from: Option<&str>) -> Result<Reply, String> {
        let ds = self.source_ds(source)?;
        if self.backup.is_some() || self.restore.is_some() {
            return Err("a session is already open".into());
        }
        let zfs = &*self.srv.zfs;
        let snaps = match zfs.exists(&ds) {
            Ok(true) => strata_snaps(zfs, &ds).map_err(|e| e.to_string()),
            Ok(false) => return err(ErrorCode::NotFound, format!("no source {source}")),
            Err(e) => Err(e.to_string()),
        };
        let snaps = match snaps {
            Ok(s) => s,
            Err(e) => return err(ErrorCode::Internal, e),
        };
        let Some(to) = snaps.iter().find(|s| s.name == snapshot) else {
            return err(ErrorCode::NotFound, format!("no snapshot {snapshot} of {source}"));
        };
        let from_snap = match from {
            None => None,
            Some(f) => match snaps.iter().find(|s| s.name == f) {
                Some(s) if s.createtxg < to.createtxg => Some(s),
                Some(_) => return err(ErrorCode::BadRequest, format!("{f} is not older than {snapshot}")),
                None => return err(ErrorCode::NotFound, format!("no snapshot {f} of {source}")),
            },
        };
        let client = self.client.clone().unwrap();
        let Some(slot) = self.srv.acquire(&client, source) else {
            return one(ZResp::Busy { retry_after_ms: BUSY_RETRY_MS });
        };
        let raw = zfs.get_prop(&ds, "encryption").ok().flatten().is_some_and(|e| e != "off");
        let (r, w) = match rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC) {
            Ok(p) => p,
            Err(e) => return err(ErrorCode::Internal, e.to_string()),
        };
        let from_full = from_snap.map(|s| format!("{ds}@{}", s.name));
        let job = match zfs.send(&format!("{ds}@{snapshot}"), from_full.as_deref(), SendFlags::standard(raw), None, w) {
            Ok(j) => j,
            Err(e) => return err(ErrorCode::Internal, e.to_string()),
        };
        self.restore = Some(Restore { _slot: slot, job });
        Ok(vec![(ZResp::RestoreReady { fromguid: from_snap.map_or(0, |s| s.guid), toguid: to.guid }, Some(r))])
    }
}
