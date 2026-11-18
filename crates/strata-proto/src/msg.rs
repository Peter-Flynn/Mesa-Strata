use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
/// Versions this build accepts from a peer: the current one and the previous one, so
/// servers and clients upgrade independently.
pub const SUPPORTED_VERSIONS: &[u16] = &[PROTOCOL_VERSION];

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Psk,
    None,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Dataset,
    Zvol,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    pub guid: u64,
    pub generation: u64,
    pub unix_time: i64,
    pub used_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    pub name: String,
    pub kind: SourceKind,
    pub snapshots: u32,
    pub newest: Option<SnapshotInfo>,
}

/// Where an interrupted `zfs receive -s` stopped, decoded by zfsd from the dataset's own
/// `receive_resume_token`. The client feeds these numbers to `lzc_send_resume`, so neither
/// client half ever parses a token string from the server.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePoint {
    pub fromguid: u64,
    pub toguid: u64,
    pub object: u64,
    pub offset: u64,
    pub raw: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HeadRef {
    pub name: String,
    pub guid: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitMeta {
    pub interval_secs: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum RestoreMode {
    Full,
    Delta { from: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    NotFound,
    Conflict,
    Validation,
    Internal,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Msg {
    ListSources,
    Sources(Vec<SourceInfo>),
    ListSnapshots {
        source: String,
    },
    Snapshots(Vec<SnapshotInfo>),
    BeginBackup {
        source: String,
        kind: SourceKind,
        base_gen: u64,
    },
    Ready {
        server_gen: u64,
        head: Option<HeadRef>,
        resume: Option<ResumePoint>,
    },
    Busy {
        retry_after_ms: u32,
    },
    /// The client can't continue the server's partial receive; the server aborts it
    /// (`zfs receive -A`) and replies with a fresh `Ready`.
    DiscardResume,
    ZfsChunk(#[serde(with = "serde_bytes")] Vec<u8>),
    Checkpoint,
    CheckpointAck,
    Commit {
        generation: u64,
        meta: CommitMeta,
    },
    Committed {
        snapshot: String,
    },
    BeginRestore {
        source: String,
        snapshot: String,
        mode: RestoreMode,
    },
    RestoreDone,
    Abort,
    Error {
        code: ErrorCode,
        message: String,
    },
}

pub const MAX_MSG: usize = 1 << 20;
pub const ZFS_CHUNK: usize = 256 * 1024;

pub fn encode(msg: &Msg, out: &mut Vec<u8>) {
    let start = out.len();
    out.extend_from_slice(&[0; 4]);
    let out_taken = std::mem::take(out);
    let mut buf = postcard::to_extend(msg, out_taken).expect("postcard to Vec");
    let len = (buf.len() - start - 4) as u32;
    buf[start..start + 4].copy_from_slice(&len.to_le_bytes());
    *out = buf;
}

pub fn decode(bytes: &[u8]) -> Result<Msg, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let msgs = vec![
            Msg::BeginBackup { source: "home".into(), kind: SourceKind::Dataset, base_gen: 3 },
            Msg::ZfsChunk(vec![1, 2, 3]),
            Msg::Ready {
                server_gen: 7,
                head: Some(HeadRef { name: "strata-x-g7".into(), guid: 99 }),
                resume: Some(ResumePoint { fromguid: 1, toguid: 2, object: 3, offset: 4, raw: false }),
            },
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            encode(m, &mut buf);
        }
        let mut rest = &buf[..];
        for m in &msgs {
            let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
            assert_eq!(&decode(&rest[4..4 + len]).unwrap(), m);
            rest = &rest[4 + len..];
        }
        assert!(rest.is_empty());
    }
}
