//! netd ↔ zfsd messages, encoded as fixed-size local messages (see `local`).
//!
//! Descriptors travel with three messages: `Connect` carries netd's accepted TCP socket
//! (sent before netd reads a byte from the network, so zfsd learns the peer address from
//! the kernel, not from netd), `ReceiveReady` carries the write end of the `zfs receive`
//! stdin pipe, and `RestoreReady` the read end of the send pipe.

use crate::hs::RejectReason;
use crate::local::{Dec, Enc, LOCAL_MSG, Malformed};
use crate::msg::{AuthMode, ErrorCode, ResumePoint, SnapshotInfo, SourceKind};

pub const NAME_MAX: usize = crate::names::MAX_NAME;
/// ZFS limits a full dataset name, snapshot part included, to 255 bytes.
pub const SNAP_MAX: usize = 255;
pub const TEXT_MAX: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZReq {
    Connect,
    Hello { version: u16, client: String, auth: AuthMode, nonce: [u8; 16] },
    CpaceA { ya: [u8; 32] },
    Confirm { ta: [u8; 64] },
    ListSources,
    ListSnapshots { source: String },
    BeginBackup { source: String, kind: SourceKind },
    DiscardResume,
    StartReceive,
    Commit { generation: u64, interval_secs: Option<u64> },
    Abort,
    BeginRestore { source: String, snapshot: String, from: Option<String> },
    RestoreStatus,
    Rebase { source: String, snapshot: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZResp {
    Ok,
    HelloOk { version: u16, server_id: [u8; 16], nonce: [u8; 16], insecure: bool },
    Reject { reason: RejectReason, retry_after_ms: u32 },
    CpaceB { yb: [u8; 32], tb: [u8; 64] },
    Authenticated { psk: [u8; 32] },
    Source { name: String, kind: SourceKind, snapshots: u32, newest: Option<SnapshotInfo> },
    Snapshot(SnapshotInfo),
    ListEnd,
    Ready { server_gen: u64, head: Option<(String, u64)>, resume: Option<ResumePoint> },
    Busy { retry_after_ms: u32 },
    ReceiveReady { expected_fromguid: u64 },
    Committed { snapshot: String },
    RestoreReady { fromguid: u64, toguid: u64 },
    Error { code: ErrorCode, message: String },
}

fn auth_to(a: AuthMode) -> u8 {
    match a {
        AuthMode::Psk => 0,
        AuthMode::None => 1,
    }
}
fn auth_from(v: u8) -> Result<AuthMode, Malformed> {
    match v {
        0 => Ok(AuthMode::Psk),
        1 => Ok(AuthMode::None),
        _ => Err(Malformed("bad auth mode")),
    }
}
pub fn kind_to(k: SourceKind) -> u8 {
    match k {
        SourceKind::Dataset => 0,
        SourceKind::Zvol => 1,
    }
}
pub fn kind_from(v: u8) -> Result<SourceKind, Malformed> {
    match v {
        0 => Ok(SourceKind::Dataset),
        1 => Ok(SourceKind::Zvol),
        _ => Err(Malformed("bad source kind")),
    }
}
pub fn code_to(c: ErrorCode) -> u8 {
    match c {
        ErrorCode::BadRequest => 0,
        ErrorCode::NotFound => 1,
        ErrorCode::Conflict => 2,
        ErrorCode::Validation => 3,
        ErrorCode::Internal => 4,
    }
}
pub fn code_from(v: u8) -> Result<ErrorCode, Malformed> {
    Ok(match v {
        0 => ErrorCode::BadRequest,
        1 => ErrorCode::NotFound,
        2 => ErrorCode::Conflict,
        3 => ErrorCode::Validation,
        4 => ErrorCode::Internal,
        _ => return Err(Malformed("bad error code")),
    })
}
const REASONS: [RejectReason; 7] = [
    RejectReason::UnsupportedVersion,
    RejectReason::UnknownClient,
    RejectReason::AuthModeMismatch,
    RejectReason::AddressNotAllowed,
    RejectReason::BackingOff,
    RejectReason::AuthFailed,
    RejectReason::Internal,
];
fn reason_to(r: RejectReason) -> u8 {
    REASONS.iter().position(|&x| x == r).unwrap() as u8
}
fn reason_from(v: u8) -> Result<RejectReason, Malformed> {
    REASONS.get(v as usize).copied().ok_or(Malformed("bad reject reason"))
}

pub fn put_snapshot(e: &mut Enc, s: &SnapshotInfo) {
    e.str(&s.name, SNAP_MAX).u64(s.guid).u64(s.generation).i64(s.unix_time).u64(s.used_bytes);
}
pub fn get_snapshot(d: &mut Dec) -> Result<SnapshotInfo, Malformed> {
    Ok(SnapshotInfo {
        name: d.str(SNAP_MAX)?,
        guid: d.u64()?,
        generation: d.u64()?,
        unix_time: d.i64()?,
        used_bytes: d.u64()?,
    })
}
const EMPTY_RESUME: ResumePoint = ResumePoint { fromguid: 0, toguid: 0, object: 0, offset: 0, raw: false };

pub fn empty_snapshot() -> SnapshotInfo {
    SnapshotInfo { name: String::new(), guid: 0, generation: 0, unix_time: 0, used_bytes: 0 }
}

/// Reads an optional snapshot written as a presence flag plus a full field; an absent
/// one must be all zero, so every value has exactly one encoding.
pub fn get_opt_snapshot(d: &mut Dec, present: bool) -> Result<Option<SnapshotInfo>, Malformed> {
    let s = get_snapshot(d)?;
    if !present && s != empty_snapshot() {
        return Err(Malformed("absent snapshot with content"));
    }
    Ok(present.then_some(s))
}

pub fn put_resume(e: &mut Enc, r: Option<&ResumePoint>) {
    let r = r.map(|r| (true, *r)).unwrap_or((false, EMPTY_RESUME));
    e.bool(r.0).u64(r.1.fromguid).u64(r.1.toguid).u64(r.1.object).u64(r.1.offset).bool(r.1.raw);
}
pub fn get_resume(d: &mut Dec) -> Result<Option<ResumePoint>, Malformed> {
    let present = d.bool()?;
    let r = ResumePoint { fromguid: d.u64()?, toguid: d.u64()?, object: d.u64()?, offset: d.u64()?, raw: d.bool()? };
    if !present && r != EMPTY_RESUME {
        return Err(Malformed("absent resume point with content"));
    }
    Ok(present.then_some(r))
}
fn put_opt_u64(e: &mut Enc, v: Option<u64>) {
    e.bool(v.is_some()).u64(v.unwrap_or(0));
}
fn get_opt_u64(d: &mut Dec) -> Result<Option<u64>, Malformed> {
    let p = d.bool()?;
    let v = d.u64()?;
    if !p && v != 0 {
        return Err(Malformed("absent number with content"));
    }
    Ok(p.then_some(v))
}

impl ZReq {
    pub fn encode(&self) -> Result<Box<[u8; LOCAL_MSG]>, Malformed> {
        match self {
            ZReq::Connect => Enc::new(1).finish(),
            ZReq::Hello { version, client, auth, nonce } => {
                Enc::new(2).u16(*version).str(client, NAME_MAX).u8(auth_to(*auth)).bytes(nonce).finish()
            }
            ZReq::CpaceA { ya } => Enc::new(3).bytes(ya).finish(),
            ZReq::Confirm { ta } => Enc::new(4).bytes(ta).finish(),
            ZReq::ListSources => Enc::new(5).finish(),
            ZReq::ListSnapshots { source } => Enc::new(6).str(source, NAME_MAX).finish(),
            ZReq::BeginBackup { source, kind } => Enc::new(7).str(source, NAME_MAX).u8(kind_to(*kind)).finish(),
            ZReq::DiscardResume => Enc::new(8).finish(),
            ZReq::StartReceive => Enc::new(9).finish(),
            ZReq::Commit { generation, interval_secs } => {
                let mut e = Enc::new(10);
                e.u64(*generation);
                put_opt_u64(&mut e, *interval_secs);
                e.finish()
            }
            ZReq::Abort => Enc::new(11).finish(),
            ZReq::BeginRestore { source, snapshot, from } => {
                Enc::new(12).str(source, NAME_MAX).str(snapshot, SNAP_MAX).opt_str(from.as_deref(), SNAP_MAX).finish()
            }
            ZReq::RestoreStatus => Enc::new(13).finish(),
            ZReq::Rebase { source, snapshot } => Enc::new(14).str(source, NAME_MAX).str(snapshot, SNAP_MAX).finish(),
        }
    }

    pub fn decode(buf: &[u8; LOCAL_MSG]) -> Result<ZReq, Malformed> {
        let mut d = Dec::new(buf);
        let r = match d.u16()? {
            1 => ZReq::Connect,
            2 => ZReq::Hello {
                version: d.u16()?,
                client: d.str(NAME_MAX)?,
                auth: auth_from(d.u8()?)?,
                nonce: d.array()?,
            },
            3 => ZReq::CpaceA { ya: d.array()? },
            4 => ZReq::Confirm { ta: d.array()? },
            5 => ZReq::ListSources,
            6 => ZReq::ListSnapshots { source: d.str(NAME_MAX)? },
            7 => ZReq::BeginBackup { source: d.str(NAME_MAX)?, kind: kind_from(d.u8()?)? },
            8 => ZReq::DiscardResume,
            9 => ZReq::StartReceive,
            10 => ZReq::Commit { generation: d.u64()?, interval_secs: get_opt_u64(&mut d)? },
            11 => ZReq::Abort,
            12 => {
                ZReq::BeginRestore { source: d.str(NAME_MAX)?, snapshot: d.str(SNAP_MAX)?, from: d.opt_str(SNAP_MAX)? }
            }
            13 => ZReq::RestoreStatus,
            14 => ZReq::Rebase { source: d.str(NAME_MAX)?, snapshot: d.str(SNAP_MAX)? },
            _ => return Err(Malformed("unknown request tag")),
        };
        d.finish()?;
        Ok(r)
    }
}

impl ZResp {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> ZResp {
        let mut message: String = message.into();
        if message.len() > TEXT_MAX {
            let mut cut = TEXT_MAX;
            while !message.is_char_boundary(cut) {
                cut -= 1;
            }
            message.truncate(cut);
        }
        ZResp::Error { code, message: message.replace('\0', " ") }
    }

    pub fn encode(&self) -> Result<Box<[u8; LOCAL_MSG]>, Malformed> {
        match self {
            ZResp::Ok => Enc::new(1).finish(),
            ZResp::HelloOk { version, server_id, nonce, insecure } => {
                Enc::new(2).u16(*version).bytes(server_id).bytes(nonce).bool(*insecure).finish()
            }
            ZResp::Reject { reason, retry_after_ms } => {
                Enc::new(3).u8(reason_to(*reason)).u32(*retry_after_ms).finish()
            }
            ZResp::CpaceB { yb, tb } => Enc::new(4).bytes(yb).bytes(tb).finish(),
            ZResp::Authenticated { psk } => Enc::new(5).bytes(psk).finish(),
            ZResp::Source { name, kind, snapshots, newest } => {
                let mut e = Enc::new(6);
                e.str(name, NAME_MAX).u8(kind_to(*kind)).u32(*snapshots).bool(newest.is_some());
                put_snapshot(&mut e, newest.as_ref().unwrap_or(&empty_snapshot()));
                e.finish()
            }
            ZResp::Snapshot(s) => {
                let mut e = Enc::new(7);
                put_snapshot(&mut e, s);
                e.finish()
            }
            ZResp::ListEnd => Enc::new(8).finish(),
            ZResp::Ready { server_gen, head, resume } => {
                let mut e = Enc::new(9);
                e.u64(*server_gen)
                    .opt_str(head.as_ref().map(|h| h.0.as_str()), SNAP_MAX)
                    .u64(head.as_ref().map_or(0, |h| h.1));
                put_resume(&mut e, resume.as_ref());
                e.finish()
            }
            ZResp::Busy { retry_after_ms } => Enc::new(10).u32(*retry_after_ms).finish(),
            ZResp::ReceiveReady { expected_fromguid } => Enc::new(11).u64(*expected_fromguid).finish(),
            ZResp::Committed { snapshot } => Enc::new(12).str(snapshot, SNAP_MAX).finish(),
            ZResp::RestoreReady { fromguid, toguid } => Enc::new(13).u64(*fromguid).u64(*toguid).finish(),
            ZResp::Error { code, message } => Enc::new(14).u8(code_to(*code)).str(message, TEXT_MAX).finish(),
        }
    }

    pub fn decode(buf: &[u8; LOCAL_MSG]) -> Result<ZResp, Malformed> {
        let mut d = Dec::new(buf);
        let r = match d.u16()? {
            1 => ZResp::Ok,
            2 => ZResp::HelloOk { version: d.u16()?, server_id: d.array()?, nonce: d.array()?, insecure: d.bool()? },
            3 => ZResp::Reject { reason: reason_from(d.u8()?)?, retry_after_ms: d.u32()? },
            4 => ZResp::CpaceB { yb: d.array()?, tb: d.array()? },
            5 => ZResp::Authenticated { psk: d.array()? },
            6 => {
                let name = d.str(NAME_MAX)?;
                let kind = kind_from(d.u8()?)?;
                let snapshots = d.u32()?;
                let has = d.bool()?;
                ZResp::Source { name, kind, snapshots, newest: get_opt_snapshot(&mut d, has)? }
            }
            7 => ZResp::Snapshot(get_snapshot(&mut d)?),
            8 => ZResp::ListEnd,
            9 => {
                let server_gen = d.u64()?;
                let name = d.opt_str(SNAP_MAX)?;
                let guid = d.u64()?;
                if name.is_none() && guid != 0 {
                    return Err(Malformed("absent head with a guid"));
                }
                let resume = get_resume(&mut d)?;
                ZResp::Ready { server_gen, head: name.map(|n| (n, guid)), resume }
            }
            10 => ZResp::Busy { retry_after_ms: d.u32()? },
            11 => ZResp::ReceiveReady { expected_fromguid: d.u64()? },
            12 => ZResp::Committed { snapshot: d.str(SNAP_MAX)? },
            13 => ZResp::RestoreReady { fromguid: d.u64()?, toguid: d.u64()? },
            14 => ZResp::Error { code: code_from(d.u8()?)?, message: d.str(TEXT_MAX)? },
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
    fn roundtrip_all() {
        let snap = SnapshotInfo { name: "strata-x-g1".into(), guid: 5, generation: 1, unix_time: 9, used_bytes: 10 };
        let reqs = vec![
            ZReq::Connect,
            ZReq::Hello { version: 1, client: "nas".into(), auth: AuthMode::None, nonce: [3; 16] },
            ZReq::CpaceA { ya: [1; 32] },
            ZReq::Confirm { ta: [2; 64] },
            ZReq::ListSnapshots { source: "home".into() },
            ZReq::BeginBackup { source: "home".into(), kind: SourceKind::Zvol },
            ZReq::Commit { generation: 4, interval_secs: Some(3600) },
            ZReq::Commit { generation: 4, interval_secs: None },
            ZReq::BeginRestore { source: "home".into(), snapshot: "s".into(), from: Some("t".into()) },
            ZReq::RestoreStatus,
            ZReq::Rebase { source: "home".into(), snapshot: "strata-x-g2".into() },
        ];
        for r in reqs {
            assert_eq!(ZReq::decode(&r.encode().unwrap()).unwrap(), r);
        }
        let resps = vec![
            ZResp::HelloOk { version: 1, server_id: [9; 16], nonce: [8; 16], insecure: true },
            ZResp::Reject { reason: RejectReason::BackingOff, retry_after_ms: 1000 },
            ZResp::CpaceB { yb: [1; 32], tb: [2; 64] },
            ZResp::Authenticated { psk: [4; 32] },
            ZResp::Source { name: "home".into(), kind: SourceKind::Dataset, snapshots: 3, newest: Some(snap.clone()) },
            ZResp::Source { name: "home".into(), kind: SourceKind::Dataset, snapshots: 0, newest: None },
            ZResp::Snapshot(snap),
            ZResp::Ready {
                server_gen: 3,
                head: Some(("strata-x-g3".into(), 77)),
                resume: Some(ResumePoint { fromguid: 1, toguid: 2, object: 3, offset: 4, raw: true }),
            },
            ZResp::Ready { server_gen: 0, head: None, resume: None },
            ZResp::Committed { snapshot: "strata-x-g4".into() },
            ZResp::error(ErrorCode::Validation, "bad\0stream"),
        ];
        for r in resps {
            assert_eq!(ZResp::decode(&r.encode().unwrap()).unwrap(), r);
        }
    }
}
