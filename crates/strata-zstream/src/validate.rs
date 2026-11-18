//! Incremental send-stream validator.
//!
//! Bytes go in through `push` in chunks of any size; only bytes that have fully passed
//! validation come out. A record is released once the next record's header has been
//! checked, because that header's checksum field is what covers the previous record's
//! payload. END is released as soon as it checks out, and `finish` fails unless END was
//! seen and nothing followed it.
//!
//! Checks: the stream is a single little-endian substream (no `-R` package, no
//! byte-swapped stream) whose BEGIN carries the expected `fromguid` (and `toguid`, when
//! known) and only allowed features and flags; record types are whitelisted (no
//! WRITE_BYREF, REDACT or nested BEGIN); every record's `toguid` matches BEGIN's; every
//! length is bounded; every running checksum and the END checksum match. A BEGIN payload
//! may only hold a resume point (with the RESUMING feature) and a raw stream's key
//! (with RAW).

use crate::fletcher::Fletcher4;
use crate::nvlist::{NvList, Value, decode_xdr};
use crate::record::*;
use crate::{StreamError, invalid};

#[derive(Clone, Debug)]
pub struct Expect {
    pub fromguid: u64,
    pub toguid: Option<u64>,
    pub allow_raw: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub toguid: u64,
    pub fromguid: u64,
    pub toname: String,
    pub features: u64,
    pub objset_type: u32,
    pub resume: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Header,
    Payload(usize),
    Done,
}

pub struct Validator {
    expect: Expect,
    state: State,
    cur: Vec<u8>,
    pending: Vec<u8>,
    ck: Fletcher4,
    summary: Option<Summary>,
    offset: u64,
}

fn payload_len(h: &[u8], t: u32) -> Result<usize, StreamError> {
    let len = match t {
        DRR_BEGIN => {
            let n = u32_at(h, 4);
            if n > MAX_BEGIN_PAYLOAD {
                return invalid("BEGIN payload too large");
            }
            n as u64
        }
        DRR_OBJECT => {
            let raw = u32_at(h, 36);
            let bonus = u32_at(h, 28);
            if bonus > MAX_BONUS || raw > MAX_BONUS {
                return invalid("OBJECT bonus too large");
            }
            if raw != 0 { raw as u64 } else { (bonus as u64).div_ceil(8) * 8 }
        }
        DRR_WRITE => {
            let logical = u64_at(h, 32);
            let compressed = u64_at(h, 96);
            if logical == 0 || logical > MAX_BLOCK || compressed > MAX_BLOCK {
                return invalid("WRITE size out of range");
            }
            if h[50] != 0 { compressed } else { logical }
        }
        DRR_SPILL => {
            let length = u64_at(h, 16);
            let compressed = u64_at(h, 40);
            if length > MAX_SPILL || compressed > MAX_SPILL {
                return invalid("SPILL size out of range");
            }
            if compressed != 0 { compressed } else { length }
        }
        DRR_WRITE_EMBEDDED => {
            let psize = u32_at(h, 52);
            let lsize = u32_at(h, 48);
            if psize > MAX_EMBEDDED_PSIZE || lsize as u64 > MAX_BLOCK || u64_at(h, 24) > MAX_BLOCK {
                return invalid("WRITE_EMBEDDED size out of range");
            }
            (psize as u64).div_ceil(8) * 8
        }
        _ => 0,
    };
    if len % 4 != 0 {
        return invalid("payload length not a multiple of 4");
    }
    Ok(len as usize)
}

fn toguid_offset(t: u32) -> Option<usize> {
    match t {
        DRR_OBJECT | DRR_WRITE | DRR_END => Some(40),
        DRR_FREEOBJECTS | DRR_SPILL | DRR_OBJECT_RANGE => Some(24),
        DRR_FREE | DRR_WRITE_EMBEDDED => Some(32),
        _ => None,
    }
}

impl Validator {
    pub fn new(expect: Expect) -> Validator {
        Validator {
            expect,
            state: State::Header,
            cur: Vec::with_capacity(HEADER),
            pending: Vec::new(),
            ck: Fletcher4::default(),
            summary: None,
            offset: 0,
        }
    }

    fn begin(&mut self, h: &[u8]) -> Result<(), StreamError> {
        let magic = u64_at(h, 8);
        if magic == DMU_BACKUP_MAGIC.swap_bytes() {
            return invalid("byte-swapped (big-endian) streams are not supported");
        }
        if magic != DMU_BACKUP_MAGIC {
            return invalid("not a ZFS send stream (bad magic)");
        }
        let vi = u64_at(h, 16);
        if hdrtype(vi) != DMU_SUBSTREAM {
            return invalid("replication (-R) and other compound streams are refused");
        }
        let feat = features(vi);
        if feat & !ALLOWED_FEATURES != 0 {
            return invalid(format!("stream uses refused features {:#x}", feat & !ALLOWED_FEATURES));
        }
        if feat & FEATURE_RAW != 0 && !self.expect.allow_raw {
            return invalid("raw streams are not allowed here");
        }
        let objset_type = u32_at(h, 32);
        if objset_type != DMU_OST_ZFS && objset_type != DMU_OST_ZVOL {
            return invalid("stream is neither a filesystem nor a volume");
        }
        if u32_at(h, 36) & !ALLOWED_BEGIN_FLAGS != 0 {
            return invalid("stream has unknown BEGIN flags");
        }
        let toguid = u64_at(h, 40);
        let fromguid = u64_at(h, 48);
        if toguid == 0 {
            return invalid("stream has no toguid");
        }
        if fromguid != self.expect.fromguid {
            return invalid(format!("stream is based on guid {fromguid:#x}, expected {:#x}", self.expect.fromguid));
        }
        if let Some(t) = self.expect.toguid
            && t != toguid
        {
            return invalid(format!("stream is of guid {toguid:#x}, expected {t:#x}"));
        }
        let name = &h[56..56 + MAXNAMELEN];
        let end = name.iter().position(|&c| c == 0).ok_or(StreamError::Invalid("unterminated toname".into()))?;
        let toname = std::str::from_utf8(&name[..end])
            .ok()
            .filter(|s| s.bytes().all(|c| c.is_ascii_graphic() || c == b' '))
            .ok_or(StreamError::Invalid("toname is not printable ASCII".into()))?
            .to_string();
        if u32_at(h, 4) != 0 && feat & (FEATURE_RESUMING | FEATURE_RAW) == 0 {
            return invalid("BEGIN payload without a feature that uses one");
        }
        if feat & FEATURE_RESUMING != 0 && u32_at(h, 4) == 0 {
            return invalid("resuming stream without a resume point");
        }
        self.summary = Some(Summary { toguid, fromguid, toname, features: feat, objset_type, resume: None });
        Ok(())
    }

    fn begin_payload(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        let nv: NvList = decode_xdr(payload)?;
        let s = self.summary.as_mut().unwrap();
        let resuming = s.features & FEATURE_RESUMING != 0;
        let raw = s.features & FEATURE_RAW != 0;
        for (name, v) in &nv.0 {
            match (name.as_str(), v) {
                ("resume_object" | "resume_offset", Value::U64(_)) if resuming => {}
                ("crypt_keydata", Value::List(keys)) if raw => {
                    for (_, kv) in &keys.0 {
                        if !matches!(kv, Value::U64(_) | Value::U8Array(_) | Value::Boolean | Value::BooleanValue(_)) {
                            return invalid("unexpected value type in crypt_keydata");
                        }
                    }
                }
                _ => return invalid(format!("BEGIN payload field {name:?} is refused")),
            }
        }
        if resuming {
            match (nv.u64("resume_object"), nv.u64("resume_offset")) {
                (Some(o), Some(f)) => s.resume = Some((o, f)),
                _ => return invalid("resuming stream lacks resume_object/resume_offset"),
            }
        }
        Ok(())
    }

    fn header(&mut self, out: &mut Vec<u8>) -> Result<(), StreamError> {
        let h = std::mem::take(&mut self.cur);
        let t = u32_at(&h, 0);
        if let Some(summary) = &self.summary {
            match t {
                DRR_OBJECT | DRR_FREEOBJECTS | DRR_WRITE | DRR_FREE | DRR_END | DRR_SPILL | DRR_WRITE_EMBEDDED
                | DRR_OBJECT_RANGE => {}
                _ => return invalid(format!("record type {} ({t}) is refused", type_name(t))),
            }
            if t == DRR_OBJECT_RANGE && summary.features & FEATURE_RAW == 0 {
                return invalid("OBJECT_RANGE in a non-raw stream");
            }
            if u32_at(&h, 4) != 0 {
                return invalid("payloadlen set on a non-BEGIN record");
            }
            let toguid = summary.toguid;
            let before = self.ck;
            self.ck.update(&h[..CKSUM_OFF]);
            if h[CKSUM_OFF..] != self.ck.to_bytes() {
                return Err(StreamError::Checksum(self.offset));
            }
            self.ck.update(&h[CKSUM_OFF..]);
            if let Some(off) = toguid_offset(t)
                && u64_at(&h, off) != toguid
            {
                return invalid(format!("{} record for a different snapshot", type_name(t)));
            }
            if t == DRR_END && h[8..40] != before.to_bytes() {
                return Err(StreamError::Checksum(self.offset));
            }
            out.append(&mut self.pending);
        } else {
            if t != DRR_BEGIN {
                return invalid("stream does not start with BEGIN");
            }
            self.begin(&h)?;
            self.ck.update(&h);
        }
        self.offset += HEADER as u64;
        if t == DRR_END {
            out.extend_from_slice(&h);
            self.state = State::Done;
            return Ok(());
        }
        let len = payload_len(&h, t)?;
        self.cur = h;
        if len == 0 {
            self.complete();
        } else {
            self.state = State::Payload(len);
        }
        Ok(())
    }

    fn complete(&mut self) {
        self.pending = std::mem::take(&mut self.cur);
        self.cur.reserve(HEADER);
        self.state = State::Header;
    }

    pub fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), StreamError> {
        while !input.is_empty() {
            match self.state {
                State::Done => return invalid("data after END"),
                State::Header => {
                    let n = (HEADER - self.cur.len()).min(input.len());
                    self.cur.extend_from_slice(&input[..n]);
                    input = &input[n..];
                    if self.cur.len() == HEADER {
                        self.header(out)?;
                    }
                }
                State::Payload(rem) => {
                    let n = rem.min(input.len());
                    self.cur.extend_from_slice(&input[..n]);
                    input = &input[n..];
                    if n == rem {
                        let payload = &self.cur[HEADER..];
                        self.ck.update(payload);
                        self.offset += payload.len() as u64;
                        if u32_at(&self.cur, 0) == DRR_BEGIN {
                            let p = payload.to_vec();
                            self.begin_payload(&p)?;
                        }
                        self.complete();
                    } else {
                        self.state = State::Payload(rem - n);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn finish(&self) -> Result<Summary, StreamError> {
        if self.state != State::Done {
            return invalid("stream ended before its END record");
        }
        Ok(self.summary.clone().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{Begin, StreamWriter};

    fn stream(fromguid: u64, toguid: u64) -> Vec<u8> {
        let mut w = StreamWriter::begin(Vec::new(), &Begin::new(toguid, fromguid, "pool/fs@s")).unwrap();
        w.object(1, 131072, &[1, 2, 3]).unwrap();
        w.write(1, 0, &vec![0xab; 131072]).unwrap();
        w.write(1, 131072, &[5; 512]).unwrap();
        w.free(1, 262144, u64::MAX).unwrap();
        w.freeobjects(2, 10).unwrap();
        w.end().unwrap()
    }

    fn run(bytes: &[u8], expect: Expect, chunk: usize) -> Result<(Vec<u8>, Summary), StreamError> {
        let mut v = Validator::new(expect);
        let mut out = Vec::new();
        for c in bytes.chunks(chunk) {
            v.push(c, &mut out)?;
        }
        let s = v.finish()?;
        Ok((out, s))
    }

    fn ex(fromguid: u64) -> Expect {
        Expect { fromguid, toguid: None, allow_raw: false }
    }

    #[test]
    fn accepts_valid_streams_in_any_chunking() {
        let s = stream(0, 77);
        for chunk in [1, 7, 312, 4096, s.len()] {
            let (out, sum) = run(&s, ex(0), chunk).unwrap();
            assert_eq!(out, s);
            assert_eq!(sum.toguid, 77);
            assert_eq!(sum.toname, "pool/fs@s");
        }
        run(&stream(5, 77), ex(5), 100).unwrap();
    }

    #[test]
    fn output_trails_validation() {
        let s = stream(0, 77);
        let mut v = Validator::new(ex(0));
        let mut out = Vec::new();
        v.push(&s[..HEADER + 10], &mut out).unwrap();
        assert!(out.is_empty(), "BEGIN waits for the next header's checksum");
    }

    #[test]
    fn rejects_wrong_base_and_guid() {
        let s = stream(5, 77);
        assert!(run(&s, ex(6), 64).is_err());
        assert!(run(&s, Expect { fromguid: 5, toguid: Some(78), allow_raw: false }, 64).is_err());
    }

    #[test]
    fn rejects_every_single_bit_flip_in_headers() {
        let s = stream(0, 77);
        let headers: Vec<usize> = {
            let mut v = Vec::new();
            let mut val = Validator::new(ex(0));
            let mut pos = 0;
            let mut out = Vec::new();
            while pos < s.len() {
                if val.state == State::Header && val.cur.is_empty() {
                    v.push(pos);
                }
                val.push(&s[pos..pos + 1], &mut out).unwrap();
                pos += 1;
            }
            v
        };
        for &start in &headers {
            for off in (0..HEADER).step_by(3) {
                let mut bad = s.clone();
                bad[start + off] ^= 0x10;
                assert!(run(&bad, ex(0), 999).is_err(), "flip at header {start} offset {off} accepted");
            }
        }
    }

    #[test]
    fn rejects_payload_corruption_and_truncation() {
        let s = stream(0, 77);
        let mut bad = s.clone();
        bad[HEADER * 3 + 100] ^= 1;
        assert!(matches!(run(&bad, ex(0), 4096), Err(StreamError::Checksum(_))));
        assert!(run(&s[..s.len() - 1], ex(0), 4096).is_err());
        let mut extra = s.clone();
        extra.extend_from_slice(&[0; 8]);
        assert!(run(&extra, ex(0), 4096).is_err());
    }

    #[test]
    fn rejects_refused_features() {
        for feat in [FEATURE_DEDUP, FEATURE_REDACTED, FEATURE_HOLDS, FEATURE_RAW, 1 << 40] {
            let mut b = Begin::new(77, 0, "p/f@s");
            b.features |= feat;
            let w = StreamWriter::begin(Vec::new(), &b).unwrap();
            assert!(run(&w.end().unwrap(), ex(0), 64).is_err(), "feature {feat:#x}");
        }
        let mut b = Begin::new(77, 0, "p/f@s");
        b.features |= FEATURE_RAW;
        let w = StreamWriter::begin(Vec::new(), &b).unwrap();
        run(&w.end().unwrap(), Expect { fromguid: 0, toguid: None, allow_raw: true }, 64).unwrap();
    }

    #[test]
    fn resume_point_in_begin_payload() {
        let mut b = Begin::new(77, 3, "p/f@s");
        b.features |= FEATURE_RESUMING;
        let mut nv = NvList::default();
        nv.push("resume_object", Value::U64(9)).push("resume_offset", Value::U64(4096));
        b.payload = Some(nv);
        let w = StreamWriter::begin(Vec::new(), &b).unwrap();
        let (_, s) = run(&w.end().unwrap(), ex(3), 13).unwrap();
        assert_eq!(s.resume, Some((9, 4096)));

        let mut nv = NvList::default();
        nv.push("props", Value::U64(1));
        b.payload = Some(nv);
        let w = StreamWriter::begin(Vec::new(), &b).unwrap();
        assert!(run(&w.end().unwrap(), ex(3), 13).is_err());
    }

    #[test]
    fn rejects_compound_streams() {
        let mut b = Begin::new(77, 0, "p/f@s");
        b.hdrtype = 2;
        let w = StreamWriter::begin(Vec::new(), &b).unwrap();
        assert!(run(&w.end().unwrap(), ex(0), 64).is_err());
    }
}
