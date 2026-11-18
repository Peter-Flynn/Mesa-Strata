//! Messages between the client's ZFS half (or the root CLI) and its network half, as
//! fixed-size local messages. `Stream` carries the read end of the send pipe and `Restore`
//! the write end of the `zfs receive` pipe.

use strata_proto::local::{Dec, Enc, LOCAL_MSG, Malformed};
use strata_proto::msg::{AuthMode, ErrorCode, ResumePoint, SnapshotInfo, SourceKind};
use strata_proto::zipc::{
    NAME_MAX, SNAP_MAX, TEXT_MAX, code_from, code_to, empty_snapshot, get_opt_snapshot, get_resume, get_snapshot,
    kind_from, kind_to, put_resume, put_snapshot,
};

pub const ADDR_MAX: usize = 255;
pub const SECRET_MAX: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    None,
    Password(Vec<u8>),
    Key([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CReq {
    Init { server: String, client: String, mode: AuthMode, secret: Secret },
    ListSources,
    ListSnapshots { source: String },
    Backup { source: String, kind: SourceKind },
    DiscardResume,
    Stream,
    StreamDone { ok: bool, interval_secs: Option<u64> },
    Restore { source: String, snapshot: String, from: Option<String>, fromguid: u64, toguid: u64 },
    Abort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CResp {
    Ok,
    Ready { server_gen: u64, head: Option<(String, u64)>, resume: Option<ResumePoint> },
    Busy { retry_after_ms: u32 },
    Source { name: String, kind: SourceKind, snapshots: u32, newest: Option<SnapshotInfo> },
    Snapshot(SnapshotInfo),
    ListEnd,
    Committed { snapshot: String },
    Restored,
    Error { code: ErrorCode, message: String },
}

impl CReq {
    pub fn encode(&self) -> Result<Box<[u8; LOCAL_MSG]>, Malformed> {
        match self {
            CReq::Init { server, client, mode, secret } => {
                let mut e = Enc::new(1);
                e.str(server, ADDR_MAX).str(client, NAME_MAX).u8(matches!(mode, AuthMode::None) as u8);
                let (kind, bytes): (u8, &[u8]) = match secret {
                    Secret::None => (0, &[]),
                    Secret::Password(p) => (1, p),
                    Secret::Key(k) => (2, k),
                };
                if bytes.len() > SECRET_MAX {
                    return Err(Malformed("secret too long"));
                }
                e.u8(kind).u16(bytes.len() as u16).bytes(bytes);
                e.bytes(&vec![0u8; SECRET_MAX - bytes.len()]);
                e.finish()
            }
            CReq::ListSources => Enc::new(2).finish(),
            CReq::ListSnapshots { source } => Enc::new(3).str(source, NAME_MAX).finish(),
            CReq::Backup { source, kind } => Enc::new(4).str(source, NAME_MAX).u8(kind_to(*kind)).finish(),
            CReq::DiscardResume => Enc::new(5).finish(),
            CReq::Stream => Enc::new(6).finish(),
            CReq::StreamDone { ok, interval_secs } => {
                Enc::new(7).bool(*ok).bool(interval_secs.is_some()).u64(interval_secs.unwrap_or(0)).finish()
            }
            CReq::Restore { source, snapshot, from, fromguid, toguid } => Enc::new(8)
                .str(source, NAME_MAX)
                .str(snapshot, SNAP_MAX)
                .opt_str(from.as_deref(), SNAP_MAX)
                .u64(*fromguid)
                .u64(*toguid)
                .finish(),
            CReq::Abort => Enc::new(9).finish(),
        }
    }

    pub fn decode(buf: &[u8; LOCAL_MSG]) -> Result<CReq, Malformed> {
        let mut d = Dec::new(buf);
        let r = match d.u16()? {
            1 => {
                let server = d.str(ADDR_MAX)?;
                let client = d.str(NAME_MAX)?;
                let mode = match d.u8()? {
                    0 => AuthMode::Psk,
                    1 => AuthMode::None,
                    _ => return Err(Malformed("bad mode")),
                };
                let kind = d.u8()?;
                let len = d.u16()? as usize;
                if len > SECRET_MAX {
                    return Err(Malformed("secret too long"));
                }
                let mut field = vec![0u8; SECRET_MAX];
                for b in field.iter_mut() {
                    *b = d.u8()?;
                }
                if field[len..].iter().any(|&b| b != 0) {
                    return Err(Malformed("nonzero secret padding"));
                }
                let secret = match (kind, len) {
                    (0, 0) => Secret::None,
                    (1, _) => Secret::Password(field[..len].to_vec()),
                    (2, 32) => Secret::Key(field[..32].try_into().unwrap()),
                    _ => return Err(Malformed("bad secret")),
                };
                CReq::Init { server, client, mode, secret }
            }
            2 => CReq::ListSources,
            3 => CReq::ListSnapshots { source: d.str(NAME_MAX)? },
            4 => CReq::Backup { source: d.str(NAME_MAX)?, kind: kind_from(d.u8()?)? },
            5 => CReq::DiscardResume,
            6 => CReq::Stream,
            7 => {
                let ok = d.bool()?;
                let has = d.bool()?;
                let v = d.u64()?;
                if !has && v != 0 {
                    return Err(Malformed("absent interval with content"));
                }
                CReq::StreamDone { ok, interval_secs: has.then_some(v) }
            }
            8 => CReq::Restore {
                source: d.str(NAME_MAX)?,
                snapshot: d.str(SNAP_MAX)?,
                from: d.opt_str(SNAP_MAX)?,
                fromguid: d.u64()?,
                toguid: d.u64()?,
            },
            9 => CReq::Abort,
            _ => return Err(Malformed("unknown request tag")),
        };
        d.finish()?;
        Ok(r)
    }
}

impl CResp {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> CResp {
        let mut m: String = message.into().replace('\0', " ");
        if m.len() > TEXT_MAX {
            let mut cut = TEXT_MAX;
            while !m.is_char_boundary(cut) {
                cut -= 1;
            }
            m.truncate(cut);
        }
        CResp::Error { code, message: m }
    }

    pub fn encode(&self) -> Result<Box<[u8; LOCAL_MSG]>, Malformed> {
        match self {
            CResp::Ok => Enc::new(1).finish(),
            CResp::Ready { server_gen, head, resume } => {
                let mut e = Enc::new(2);
                e.u64(*server_gen).opt_str(head.as_ref().map(|h| h.0.as_str()), SNAP_MAX).u64(head.as_ref().map_or(0, |h| h.1));
                put_resume(&mut e, resume.as_ref());
                e.finish()
            }
            CResp::Busy { retry_after_ms } => Enc::new(3).u32(*retry_after_ms).finish(),
            CResp::Source { name, kind, snapshots, newest } => {
                let mut e = Enc::new(4);
                e.str(name, NAME_MAX).u8(kind_to(*kind)).u32(*snapshots).bool(newest.is_some());
                put_snapshot(&mut e, newest.as_ref().unwrap_or(&empty_snapshot()));
                e.finish()
            }
            CResp::Snapshot(s) => {
                let mut e = Enc::new(5);
                put_snapshot(&mut e, s);
                e.finish()
            }
            CResp::ListEnd => Enc::new(6).finish(),
            CResp::Committed { snapshot } => Enc::new(7).str(snapshot, SNAP_MAX).finish(),
            CResp::Restored => Enc::new(8).finish(),
            CResp::Error { code, message } => Enc::new(9).u8(code_to(*code)).str(message, TEXT_MAX).finish(),
        }
    }

    pub fn decode(buf: &[u8; LOCAL_MSG]) -> Result<CResp, Malformed> {
        let mut d = Dec::new(buf);
        let r = match d.u16()? {
            1 => CResp::Ok,
            2 => {
                let server_gen = d.u64()?;
                let name = d.opt_str(SNAP_MAX)?;
                let guid = d.u64()?;
                if name.is_none() && guid != 0 {
                    return Err(Malformed("absent head with a guid"));
                }
                CResp::Ready { server_gen, head: name.map(|n| (n, guid)), resume: get_resume(&mut d)? }
            }
            3 => CResp::Busy { retry_after_ms: d.u32()? },
            4 => {
                let name = d.str(NAME_MAX)?;
                let kind = kind_from(d.u8()?)?;
                let snapshots = d.u32()?;
                let has = d.bool()?;
                CResp::Source { name, kind, snapshots, newest: get_opt_snapshot(&mut d, has)? }
            }
            5 => CResp::Snapshot(get_snapshot(&mut d)?),
            6 => CResp::ListEnd,
            7 => CResp::Committed { snapshot: d.str(SNAP_MAX)? },
            8 => CResp::Restored,
            9 => CResp::Error { code: code_from(d.u8()?)?, message: d.str(TEXT_MAX)? },
            _ => return Err(Malformed("unknown response tag")),
        };
        d.finish()?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let reqs = vec![
            CReq::Init { server: "b:7420".into(), client: "nas".into(), mode: AuthMode::Psk, secret: Secret::Password(b"pw".to_vec()) },
            CReq::Init { server: "b:7420".into(), client: "nas".into(), mode: AuthMode::Psk, secret: Secret::Key([5; 32]) },
            CReq::Init { server: "b:7420".into(), client: "nas".into(), mode: AuthMode::None, secret: Secret::None },
            CReq::Backup { source: "home".into(), kind: SourceKind::Zvol },
            CReq::StreamDone { ok: true, interval_secs: Some(60) },
            CReq::Restore { source: "h".into(), snapshot: "s".into(), from: None, fromguid: 0, toguid: 9 },
        ];
        for r in reqs {
            assert_eq!(CReq::decode(&r.encode().unwrap()).unwrap(), r);
        }
        let resps = vec![
            CResp::Ready { server_gen: 1, head: Some(("x".into(), 2)), resume: None },
            CResp::Busy { retry_after_ms: 5 },
            CResp::Committed { snapshot: "s".into() },
            CResp::error(ErrorCode::NotFound, "nope"),
        ];
        for r in resps {
            assert_eq!(CResp::decode(&r.encode().unwrap()).unwrap(), r);
        }
    }
}
