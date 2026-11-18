//! `dmu_replay_record_t` layout (OpenZFS include/sys/zfs_ioctl.h), little-endian.
//!
//! Every record header is 312 bytes: `drr_type u32 @0`, `drr_payloadlen u32 @4`, then a
//! 304-byte union. For every type but BEGIN, the last 32 bytes (@280) hold the fletcher-4
//! of the stream up to that point. Field offsets below are absolute within the header.
//!
//! ```text
//! BEGIN         magic u64@8 versioninfo u64@16 creation u64@24 type u32@32 flags u32@36
//!               toguid u64@40 fromguid u64@48 toname [256]@56
//! END           checksum [32]@8 toguid u64@40
//! OBJECT        object@8 type u32@16 bonustype u32@20 blksz u32@24 bonuslen u32@28
//!               checksumtype u8@32 compress u8@33 dn_slots u8@34 flags u8@35
//!               raw_bonuslen u32@36 toguid@40 indblkshift u8@48 nlevels u8@49 nblkptr u8@50
//!               maxblkid@56
//! FREEOBJECTS   firstobj@8 numobjs@16 toguid@24
//! WRITE         object@8 type u32@16 offset@24 logical_size@32 toguid@40
//!               checksumtype u8@48 flags u8@49 compressiontype u8@50 key [40]@56
//!               compressed_size@96 salt [8]@104 iv [12]@112 mac [16]@124
//! FREE          object@8 offset@16 length@24 toguid@32
//! SPILL         object@8 length@16 toguid@24 flags u8@32 compressiontype u8@33
//!               compressed_size@40 salt@48 iv@56 mac@68 type u32@84
//! WRITE_EMBEDDED object@8 offset@16 length@24 toguid@32 compression u8@40 etype u8@41
//!               lsize u32@48 psize u32@52
//! OBJECT_RANGE  firstobj@8 numslots@16 toguid@24 salt@32 iv@40 mac@52 flags u8@68
//! ```
//!
//! Payload lengths: BEGIN `drr_payloadlen`; OBJECT `raw_bonuslen` or `bonuslen` rounded up
//! to 8; WRITE `compressed_size` when `compressiontype != 0`, else `logical_size`; SPILL
//! `compressed_size` when nonzero, else `length`; WRITE_EMBEDDED `psize` rounded up to 8.

pub const HEADER: usize = 312;
pub const CKSUM_OFF: usize = 280;

pub const DRR_BEGIN: u32 = 0;
pub const DRR_OBJECT: u32 = 1;
pub const DRR_FREEOBJECTS: u32 = 2;
pub const DRR_WRITE: u32 = 3;
pub const DRR_FREE: u32 = 4;
pub const DRR_END: u32 = 5;
pub const DRR_WRITE_BYREF: u32 = 6;
pub const DRR_SPILL: u32 = 7;
pub const DRR_WRITE_EMBEDDED: u32 = 8;
pub const DRR_OBJECT_RANGE: u32 = 9;
pub const DRR_REDACT: u32 = 10;

pub const DMU_BACKUP_MAGIC: u64 = 0x2F5B_ACBAC;
pub const DMU_SUBSTREAM: u64 = 1;

pub const FEATURE_DEDUP: u64 = 1 << 0;
pub const FEATURE_DEDUPPROPS: u64 = 1 << 1;
pub const FEATURE_SA_SPILL: u64 = 1 << 2;
pub const FEATURE_EMBED_DATA: u64 = 1 << 16;
pub const FEATURE_LZ4: u64 = 1 << 17;
pub const FEATURE_LARGE_BLOCKS: u64 = 1 << 19;
pub const FEATURE_RESUMING: u64 = 1 << 20;
pub const FEATURE_REDACTED: u64 = 1 << 21;
pub const FEATURE_COMPRESSED: u64 = 1 << 22;
pub const FEATURE_LARGE_DNODE: u64 = 1 << 23;
pub const FEATURE_RAW: u64 = 1 << 24;
pub const FEATURE_ZSTD: u64 = 1 << 25;
pub const FEATURE_HOLDS: u64 = 1 << 26;
pub const FEATURE_SWITCH_TO_LARGE_BLOCKS: u64 = 1 << 27;
pub const FEATURE_LONGNAME: u64 = 1 << 28;
pub const FEATURE_LARGE_MICROZAP: u64 = 1 << 29;

/// Features a single-dataset `zfs send [-L] [-e] [-c] [-w] [-t]` stream can carry.
/// Dedup streams, redacted streams and `-h` hold records are refused.
pub const ALLOWED_FEATURES: u64 = FEATURE_SA_SPILL
    | FEATURE_EMBED_DATA
    | FEATURE_LZ4
    | FEATURE_LARGE_BLOCKS
    | FEATURE_RESUMING
    | FEATURE_COMPRESSED
    | FEATURE_LARGE_DNODE
    | FEATURE_RAW
    | FEATURE_ZSTD
    | FEATURE_SWITCH_TO_LARGE_BLOCKS
    | FEATURE_LONGNAME
    | FEATURE_LARGE_MICROZAP;

pub const DRR_FLAG_CLONE: u32 = 1 << 0;
pub const DRR_FLAG_CI_DATA: u32 = 1 << 1;
pub const DRR_FLAG_FREERECORDS: u32 = 1 << 2;
pub const DRR_FLAG_SPILL_BLOCK: u32 = 1 << 3;
pub const ALLOWED_BEGIN_FLAGS: u32 = DRR_FLAG_CLONE | DRR_FLAG_CI_DATA | DRR_FLAG_FREERECORDS | DRR_FLAG_SPILL_BLOCK;

pub const DMU_OT_PLAIN_FILE_CONTENTS: u32 = 19;

pub const DMU_OST_ZFS: u32 = 2;
pub const DMU_OST_ZVOL: u32 = 3;

pub const MAXNAMELEN: usize = 256;
/// `SPA_MAXBLOCKSIZE`: 16 MiB.
pub const MAX_BLOCK: u64 = 16 << 20;
/// `SPA_OLD_MAXBLOCKSIZE`: spill blocks never exceed 128 KiB.
pub const MAX_SPILL: u64 = 128 << 10;
/// `BPE_PAYLOAD_SIZE`: an embedded block pointer holds at most 112 bytes.
pub const MAX_EMBEDDED_PSIZE: u32 = 112;
/// A dnode is at most 32 slots of 512 bytes, so its bonus buffer is well under 64 KiB.
pub const MAX_BONUS: u32 = 64 << 10;
/// BEGIN payloads hold at most the resume point and a raw stream's wrapped key.
pub const MAX_BEGIN_PAYLOAD: u32 = 64 << 10;

pub fn u32_at(h: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(h[off..off + 4].try_into().unwrap())
}
pub fn u64_at(h: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(h[off..off + 8].try_into().unwrap())
}
pub fn put_u32(h: &mut [u8], off: usize, v: u32) {
    h[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(h: &mut [u8], off: usize, v: u64) {
    h[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

pub fn hdrtype(versioninfo: u64) -> u64 {
    versioninfo & 0x3
}
pub fn features(versioninfo: u64) -> u64 {
    (versioninfo >> 2) & ((1u64 << 56) - 1)
}
pub fn versioninfo(hdrtype: u64, features: u64) -> u64 {
    hdrtype | (features << 2)
}

pub fn type_name(t: u32) -> &'static str {
    match t {
        DRR_BEGIN => "BEGIN",
        DRR_OBJECT => "OBJECT",
        DRR_FREEOBJECTS => "FREEOBJECTS",
        DRR_WRITE => "WRITE",
        DRR_FREE => "FREE",
        DRR_END => "END",
        DRR_WRITE_BYREF => "WRITE_BYREF",
        DRR_SPILL => "SPILL",
        DRR_WRITE_EMBEDDED => "WRITE_EMBEDDED",
        DRR_OBJECT_RANGE => "OBJECT_RANGE",
        DRR_REDACT => "REDACT",
        _ => "unknown",
    }
}
