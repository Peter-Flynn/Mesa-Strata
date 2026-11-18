//! The client's network half: holds no ZFS rights, talks to the server, and moves stream
//! bytes between the server and the descriptors the ZFS half (or root CLI) hands it.
//! Restore streams are validated here before any byte reaches the local `zfs receive`.

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use anyhow::{Context, bail};
use strata_proto::fault;
use strata_proto::hs::{ClientAuth, ClientSecret, client_handshake};
use strata_proto::local::LocalSock;
use strata_proto::msg::{AuthMode, CommitMeta, ErrorCode, Msg, RestoreMode, ZFS_CHUNK};
use strata_proto::session::Session;
use strata_zstream::{Expect, Validator};

use crate::ipc::{CReq, CResp, Secret};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub struct Settings {
    pub server: String,
    pub client: String,
    pub mode: AuthMode,
    pub secret: Option<ClientSecret>,
    pub compress_threads: usize,
}

pub fn secret_from_ipc(s: Secret) -> Option<ClientSecret> {
    match s {
        Secret::None => None,
        Secret::Password(p) => Some(ClientSecret::Password(p)),
        Secret::Key(k) => Some(ClientSecret::Key(k)),
    }
}

pub fn secret_to_ipc(s: Option<&ClientSecret>) -> Secret {
    match s {
        None => Secret::None,
        Some(ClientSecret::Password(p)) => Secret::Password(p.clone()),
        Some(ClientSecret::Key(k)) => Secret::Key(*k),
    }
}

fn connect(st: &Settings) -> anyhow::Result<Session> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = st.server.to_socket_addrs().with_context(|| format!("resolving {}", st.server))?.collect();
    let mut last = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(tcp) => {
                tcp.set_read_timeout(Some(IDLE_TIMEOUT))?;
                let auth = ClientAuth {
                    client: st.client.clone(),
                    mode: st.mode,
                    secret: st.secret.as_ref().map(|s| match s {
                        ClientSecret::Password(p) => ClientSecret::Password(p.clone()),
                        ClientSecret::Key(k) => ClientSecret::Key(*k),
                    }),
                };
                return client_handshake(tcp, &auth, st.compress_threads).map_err(anyhow::Error::from);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.map(anyhow::Error::from).unwrap_or_else(|| anyhow::anyhow!("{} resolved to no address", st.server)))
}

fn reply(local: &LocalSock, r: CResp) -> anyhow::Result<()> {
    let msg = r.encode()?;
    local.send(&msg, &[])?;
    Ok(())
}

fn msg_to_resp(m: Msg) -> CResp {
    match m {
        Msg::Busy { retry_after_ms } => CResp::Busy { retry_after_ms },
        Msg::Error { code, message } => CResp::error(code, message),
        other => CResp::error(ErrorCode::Internal, format!("unexpected reply from server: {other:?}")),
    }
}

fn remote(r: strata_proto::Result<Msg>) -> anyhow::Result<Msg> {
    match r {
        Ok(m) => Ok(m),
        Err(strata_proto::Error::Remote { code, message }) => Ok(Msg::Error { code, message }),
        Err(e) => Err(e.into()),
    }
}

/// Serves requests from one local connection until it closes. Without `settings`, the
/// first message must be `Init`.
pub fn serve(local: LocalSock, settings: Option<Settings>) -> anyhow::Result<()> {
    let mut settings = settings;
    let mut sess: Option<Session> = None;
    let mut server_gen = 0u64;
    while let Some(rcv) = local.recv()? {
        let req = CReq::decode(&rcv.msg)?;
        let mut fds = rcv.fds;
        if !matches!(req, CReq::Stream | CReq::Restore { .. }) && !fds.is_empty() {
            bail!("unexpected descriptor");
        }
        if let CReq::Init { server, client, mode, secret } = req {
            if settings.is_some() {
                bail!("Init sent twice");
            }
            settings = Some(Settings { server, client, mode, secret: secret_from_ipc(secret), compress_threads: 2 });
            reply(&local, CResp::Ok)?;
            continue;
        }
        let st = settings.as_ref().context("Init must come first")?;
        if sess.is_none() {
            match connect(st) {
                Ok(s) => sess = Some(s),
                Err(e) => {
                    reply(&local, CResp::error(ErrorCode::Internal, format!("connecting to {}: {e:#}", st.server)))?;
                    continue;
                }
            }
        }
        let s = sess.as_mut().unwrap();
        match req {
            CReq::Init { .. } => unreachable!(),
            CReq::ListSources => match remote(s.call(&Msg::ListSources))? {
                Msg::Sources(v) => {
                    for i in v {
                        reply(&local, CResp::Source { name: i.name, kind: i.kind, snapshots: i.snapshots, newest: i.newest })?;
                    }
                    reply(&local, CResp::ListEnd)?;
                }
                other => reply(&local, msg_to_resp(other))?,
            },
            CReq::ListSnapshots { source } => match remote(s.call(&Msg::ListSnapshots { source }))? {
                Msg::Snapshots(v) => {
                    for i in v {
                        reply(&local, CResp::Snapshot(i))?;
                    }
                    reply(&local, CResp::ListEnd)?;
                }
                other => reply(&local, msg_to_resp(other))?,
            },
            CReq::Backup { source, kind } => {
                let r = remote(s.call(&Msg::BeginBackup { source, kind, base_gen: 0 }))?;
                if let Msg::Ready { server_gen: g, .. } = &r {
                    server_gen = *g;
                }
                reply(&local, ready(r))?;
            }
            CReq::DiscardResume => {
                let r = remote(s.call(&Msg::DiscardResume))?;
                if let Msg::Ready { server_gen: g, .. } = &r {
                    server_gen = *g;
                }
                reply(&local, ready(r))?;
            }
            CReq::Stream => {
                let fd = fds.pop().context("Stream needs a descriptor")?;
                let mut pipe = File::from(fd);
                let mut buf = vec![0u8; ZFS_CHUNK];
                loop {
                    let n = pipe.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    s.writer.send(&Msg::ZfsChunk(buf[..n].to_vec()))?;
                }
                s.writer.flush()?;
                fault::point("client.net.streamed");
                let done = local.recv()?.context("ZFS half went away mid-backup")?;
                match CReq::decode(&done.msg)? {
                    CReq::StreamDone { ok: true, interval_secs } => {
                        let commit = Msg::Commit { generation: server_gen + 1, meta: CommitMeta { interval_secs } };
                        match remote(s.call(&commit))? {
                            Msg::Committed { snapshot } => reply(&local, CResp::Committed { snapshot })?,
                            other => reply(&local, msg_to_resp(other))?,
                        }
                    }
                    CReq::StreamDone { ok: false, .. } => {
                        s.writer.send_now(&Msg::Abort)?;
                        sess = None;
                        reply(&local, CResp::error(ErrorCode::Internal, "zfs send failed; backup aborted"))?;
                    }
                    other => bail!("expected StreamDone, got {other:?}"),
                }
            }
            CReq::StreamDone { .. } => bail!("StreamDone without Stream"),
            CReq::Abort => {
                let _ = s.writer.send_now(&Msg::Abort);
                sess = None;
                reply(&local, CResp::Ok)?;
            }
            CReq::Restore { source, snapshot, from, fromguid, toguid } => {
                let fd = fds.pop().context("Restore needs a descriptor")?;
                let r = restore(s, fd, source, snapshot, from, fromguid, toguid)?;
                if !matches!(r, CResp::Restored) {
                    sess = None;
                }
                reply(&local, r)?;
            }
        }
    }
    if let Some(s) = sess {
        let _ = s.close();
    }
    Ok(())
}

fn ready(r: Msg) -> CResp {
    match r {
        Msg::Ready { server_gen, head, resume } => CResp::Ready { server_gen, head: head.map(|h| (h.name, h.guid)), resume },
        other => msg_to_resp(other),
    }
}

fn restore(
    s: &mut Session,
    fd: OwnedFd,
    source: String,
    snapshot: String,
    from: Option<String>,
    fromguid: u64,
    toguid: u64,
) -> anyhow::Result<CResp> {
    let mode = match from {
        Some(f) => RestoreMode::Delta { from: f },
        None => RestoreMode::Full,
    };
    s.writer.send_now(&Msg::BeginRestore { source, snapshot, mode })?;
    let mut pipe = File::from(fd);
    let mut v = Validator::new(Expect { fromguid, toguid: Some(toguid), allow_raw: true });
    let mut out = Vec::with_capacity(ZFS_CHUNK * 2);
    loop {
        match remote(s.reader.recv())? {
            Msg::ZfsChunk(d) => {
                if let Err(e) = v.push(&d, &mut out) {
                    return Ok(CResp::error(ErrorCode::Validation, format!("restore stream refused: {e}")));
                }
                if let Err(e) = pipe.write_all(&out) {
                    return Ok(CResp::error(ErrorCode::Internal, format!("zfs receive stopped reading: {e}")));
                }
                out.clear();
            }
            Msg::RestoreDone => {
                if let Err(e) = v.finish() {
                    return Ok(CResp::error(ErrorCode::Validation, format!("restore stream refused: {e}")));
                }
                pipe.flush()?;
                return Ok(CResp::Restored);
            }
            other => return Ok(msg_to_resp(other)),
        }
    }
}

/// A connection from the ZFS half or the root CLI to a network half.
pub struct NetClient {
    sock: LocalSock,
}

impl NetClient {
    pub fn new(sock: LocalSock) -> NetClient {
        NetClient { sock }
    }

    pub fn send(&self, req: &CReq, fd: Option<&OwnedFd>) -> anyhow::Result<()> {
        let msg = req.encode()?;
        match fd {
            Some(f) => self.sock.send(&msg, &[f.as_fd()])?,
            None => self.sock.send(&msg, &[])?,
        }
        Ok(())
    }

    pub fn recv(&self) -> anyhow::Result<CResp> {
        let r = self.sock.recv()?.context("network half closed the connection")?;
        if !r.fds.is_empty() {
            bail!("unexpected descriptor from the network half");
        }
        Ok(CResp::decode(&r.msg)?)
    }

    pub fn call(&self, req: &CReq) -> anyhow::Result<CResp> {
        self.send(req, None)?;
        self.recv()
    }

    pub fn list(&self, req: &CReq) -> anyhow::Result<Vec<CResp>> {
        let mut out = Vec::new();
        let mut r = self.call(req)?;
        loop {
            match r {
                CResp::ListEnd => return Ok(out),
                CResp::Error { code, message } => bail!("{code:?}: {message}"),
                other => out.push(other),
            }
            r = self.recv()?;
        }
    }
}
