//! Packed nvlists (OpenZFS module/nvpair/nvpair.c), limited to the value types that send
//! streams and resume tokens use.
//!
//! Both encodings start with a 4-byte header `encoding, endian, 0, 0` (encoding 0 = native,
//! 1 = XDR) followed by `nvl_version i32, nvl_nvflag u32`.
//!
//! XDR (big-endian, 4-byte units), used in BEGIN payloads: each pair is
//! `encode_len i32, decode_len i32, name (u32 len + bytes padded to 4), type i32, nelem i32,
//! value`; values are u64 (8 bytes), boolean_value (4), string (u32 len + padded bytes),
//! uint8 array (u32 count, then 4 bytes per element), uint64 array (u32 count, then 8 per
//! element), embedded nvlist (version, nvflag, pairs, end). A list ends with two zero i32s.
//!
//! Native (little-endian here), used in resume tokens: each pair is a copy of the in-memory
//! `nvpair_t`: `nvp_size i32, name_sz i16, reserve i16, nelem i32, type i32`, the
//! NUL-terminated name at +16, and the value at `align8(16 + name_sz)`; `nvp_size` is the
//! 8-aligned total. A list ends with one zero i32.

use crate::{StreamError, invalid};

pub const DATA_TYPE_BOOLEAN: i32 = 1;
pub const DATA_TYPE_UINT64: i32 = 8;
pub const DATA_TYPE_STRING: i32 = 9;
pub const DATA_TYPE_UINT64_ARRAY: i32 = 16;
pub const DATA_TYPE_NVLIST: i32 = 19;
pub const DATA_TYPE_BOOLEAN_VALUE: i32 = 21;
pub const DATA_TYPE_UINT8_ARRAY: i32 = 26;

const NV_ENCODE_NATIVE: u8 = 0;
const NV_ENCODE_XDR: u8 = 1;
const NV_UNIQUE_NAME: u32 = 1;
const MAX_DEPTH: usize = 3;
const MAX_PAIRS: usize = 64;
const MAX_STR: usize = 1024;
const MAX_ARRAY: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Boolean,
    BooleanValue(bool),
    U64(u64),
    Str(String),
    U8Array(Vec<u8>),
    U64Array(Vec<u64>),
    List(NvList),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NvList(pub Vec<(String, Value)>);

impl NvList {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
    pub fn u64(&self, name: &str) -> Option<u64> {
        match self.get(name) {
            Some(Value::U64(v)) => Some(*v),
            _ => None,
        }
    }
    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
    pub fn push(&mut self, name: &str, v: Value) -> &mut Self {
        self.0.push((name.to_string(), v));
        self
    }
}

struct Xdr<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Xdr<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StreamError> {
        if n > self.b.len() - self.pos {
            return invalid("nvlist truncated");
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn i32(&mut self) -> Result<i32, StreamError> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, StreamError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, StreamError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<String, StreamError> {
        let len = self.u32()? as usize;
        if len > MAX_STR {
            return invalid("nvlist string too long");
        }
        let bytes = self.take(len)?;
        let pad = (4 - len % 4) % 4;
        if self.take(pad)?.iter().any(|&b| b != 0) {
            return invalid("nonzero XDR padding");
        }
        let s = std::str::from_utf8(bytes).map_err(|_| StreamError::Invalid("nvlist string not UTF-8".into()))?;
        if s.contains('\0') {
            return invalid("NUL inside nvlist string");
        }
        Ok(s.to_string())
    }
    fn count(&mut self, nelem: i32) -> Result<usize, StreamError> {
        let n = self.u32()? as usize;
        if n != nelem as usize || n > MAX_ARRAY {
            return invalid("bad nvlist array length");
        }
        Ok(n)
    }

    fn list(&mut self, depth: usize) -> Result<NvList, StreamError> {
        if depth > MAX_DEPTH {
            return invalid("nvlist nested too deep");
        }
        if self.i32()? != 0 {
            return invalid("unknown nvlist version");
        }
        let _flags = self.u32()?;
        let mut out = NvList::default();
        loop {
            let encode_len = self.i32()?;
            let decode_len = self.i32()?;
            if encode_len == 0 && decode_len == 0 {
                return Ok(out);
            }
            if encode_len <= 0 || decode_len <= 0 {
                return invalid("bad nvpair size");
            }
            if out.0.len() >= MAX_PAIRS {
                return invalid("too many nvpairs");
            }
            let name = self.string()?;
            let typ = self.i32()?;
            let nelem = self.i32()?;
            let v = match (typ, nelem) {
                (DATA_TYPE_BOOLEAN, 0) => Value::Boolean,
                (DATA_TYPE_BOOLEAN_VALUE, 1) => match self.i32()? {
                    0 => Value::BooleanValue(false),
                    1 => Value::BooleanValue(true),
                    _ => return invalid("bad boolean value"),
                },
                (DATA_TYPE_UINT64, 1) => Value::U64(self.u64()?),
                (DATA_TYPE_STRING, 1) => Value::Str(self.string()?),
                (DATA_TYPE_UINT8_ARRAY, n) if n >= 0 => {
                    let n = self.count(n)?;
                    let mut v = Vec::with_capacity(n);
                    for _ in 0..n {
                        let x = self.u32()?;
                        if x > 0xff {
                            return invalid("uint8 array element out of range");
                        }
                        v.push(x as u8);
                    }
                    Value::U8Array(v)
                }
                (DATA_TYPE_UINT64_ARRAY, n) if n >= 0 => {
                    let n = self.count(n)?;
                    let mut v = Vec::with_capacity(n);
                    for _ in 0..n {
                        v.push(self.u64()?);
                    }
                    Value::U64Array(v)
                }
                (DATA_TYPE_NVLIST, 1) => Value::List(self.list(depth + 1)?),
                _ => return invalid(format!("unsupported nvpair type {typ} for {name:?}")),
            };
            if out.has(&name) {
                return invalid("duplicate nvpair name");
            }
            out.0.push((name, v));
        }
    }
}

/// Decodes an XDR-packed nvlist; up to 7 zero bytes of padding may follow it
/// (`pad_packed_nvlist` in dmu_send.c rounds BEGIN payloads up to 8 bytes).
pub fn decode_xdr(b: &[u8]) -> Result<NvList, StreamError> {
    if b.len() < 4 || b[0] != NV_ENCODE_XDR || b[2] != 0 || b[3] != 0 {
        return invalid("not an XDR nvlist");
    }
    let mut x = Xdr { b, pos: 4 };
    let l = x.list(0)?;
    let rest = &b[x.pos..];
    if rest.len() > 7 || rest.iter().any(|&c| c != 0) {
        return invalid("trailing bytes after nvlist");
    }
    Ok(l)
}

fn xdr_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out.resize(out.len() + (4 - s.len() % 4) % 4, 0);
}

fn xdr_list(out: &mut Vec<u8>, l: &NvList) {
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&NV_UNIQUE_NAME.to_be_bytes());
    for (name, v) in &l.0 {
        let mut body = Vec::new();
        xdr_string(&mut body, name);
        let (typ, nelem): (i32, i32) = match v {
            Value::Boolean => (DATA_TYPE_BOOLEAN, 0),
            Value::BooleanValue(_) => (DATA_TYPE_BOOLEAN_VALUE, 1),
            Value::U64(_) => (DATA_TYPE_UINT64, 1),
            Value::Str(_) => (DATA_TYPE_STRING, 1),
            Value::U8Array(a) => (DATA_TYPE_UINT8_ARRAY, a.len() as i32),
            Value::U64Array(a) => (DATA_TYPE_UINT64_ARRAY, a.len() as i32),
            Value::List(_) => (DATA_TYPE_NVLIST, 1),
        };
        body.extend_from_slice(&typ.to_be_bytes());
        body.extend_from_slice(&nelem.to_be_bytes());
        match v {
            Value::Boolean => {}
            Value::BooleanValue(b) => body.extend_from_slice(&(*b as i32).to_be_bytes()),
            Value::U64(x) => body.extend_from_slice(&x.to_be_bytes()),
            Value::Str(s) => xdr_string(&mut body, s),
            Value::U8Array(a) => {
                body.extend_from_slice(&(a.len() as u32).to_be_bytes());
                for &x in a {
                    body.extend_from_slice(&(x as u32).to_be_bytes());
                }
            }
            Value::U64Array(a) => {
                body.extend_from_slice(&(a.len() as u32).to_be_bytes());
                for x in a {
                    body.extend_from_slice(&x.to_be_bytes());
                }
            }
            Value::List(l) => xdr_list(&mut body, l),
        }
        let len = (body.len() + 8) as i32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
    }
    out.extend_from_slice(&[0; 8]);
}

pub fn encode_xdr(l: &NvList) -> Vec<u8> {
    let mut out = vec![NV_ENCODE_XDR, 1, 0, 0];
    xdr_list(&mut out, l);
    out
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Decodes a native-encoded little-endian nvlist (resume tokens). Only the flat types a
/// token carries are accepted.
pub fn decode_native(b: &[u8]) -> Result<NvList, StreamError> {
    if b.len() < 12 || b[0] != NV_ENCODE_NATIVE || b[1] != 1 {
        return invalid("not a little-endian native nvlist");
    }
    let rd32 = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    if rd32(4) != 0 {
        return invalid("unknown nvlist version");
    }
    let mut pos = 12;
    let mut out = NvList::default();
    loop {
        if b.len() - pos < 4 {
            return invalid("native nvlist truncated");
        }
        let size = rd32(pos);
        if size == 0 {
            if pos + 4 != b.len() {
                return invalid("trailing bytes after native nvlist");
            }
            return Ok(out);
        }
        if size < 24 || size as usize > b.len() - pos || size % 8 != 0 {
            return invalid("bad native nvpair size");
        }
        if out.0.len() >= MAX_PAIRS {
            return invalid("too many nvpairs");
        }
        let p = &b[pos..pos + size as usize];
        let name_sz = i16::from_le_bytes(p[4..6].try_into().unwrap());
        let nelem = i32::from_le_bytes(p[8..12].try_into().unwrap());
        let typ = i32::from_le_bytes(p[12..16].try_into().unwrap());
        if name_sz < 2 || 16 + name_sz as usize > p.len() {
            return invalid("bad nvpair name size");
        }
        let name_bytes = &p[16..16 + name_sz as usize];
        if name_bytes[name_bytes.len() - 1] != 0 || name_bytes[..name_bytes.len() - 1].contains(&0) {
            return invalid("bad nvpair name");
        }
        let name = std::str::from_utf8(&name_bytes[..name_bytes.len() - 1])
            .map_err(|_| StreamError::Invalid("nvpair name not UTF-8".into()))?
            .to_string();
        let voff = align8(16 + name_sz as usize);
        let value = &p[voff.min(p.len())..];
        let v = match (typ, nelem) {
            (DATA_TYPE_BOOLEAN, 0) => Value::Boolean,
            (DATA_TYPE_UINT64, 1) if value.len() >= 8 => Value::U64(u64::from_le_bytes(value[..8].try_into().unwrap())),
            (DATA_TYPE_STRING, 1) => {
                let end = value
                    .iter()
                    .position(|&c| c == 0)
                    .ok_or(StreamError::Invalid("unterminated nvlist string".into()))?;
                if end > MAX_STR {
                    return invalid("nvlist string too long");
                }
                Value::Str(
                    std::str::from_utf8(&value[..end])
                        .map_err(|_| StreamError::Invalid("nvlist string not UTF-8".into()))?
                        .to_string(),
                )
            }
            _ => return invalid(format!("unsupported native nvpair type {typ} for {name:?}")),
        };
        if out.has(&name) {
            return invalid("duplicate nvpair name");
        }
        out.0.push((name, v));
        pos += size as usize;
    }
}

pub fn encode_native(l: &NvList) -> Vec<u8> {
    let mut out = vec![NV_ENCODE_NATIVE, 1, 0, 0];
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&NV_UNIQUE_NAME.to_le_bytes());
    for (name, v) in &l.0 {
        let name_sz = name.len() + 1;
        let (typ, nelem, value): (i32, i32, Vec<u8>) = match v {
            Value::Boolean => (DATA_TYPE_BOOLEAN, 0, Vec::new()),
            Value::U64(x) => (DATA_TYPE_UINT64, 1, x.to_le_bytes().to_vec()),
            Value::Str(s) => {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                (DATA_TYPE_STRING, 1, b)
            }
            _ => panic!("encode_native supports only boolean, uint64 and string"),
        };
        let voff = align8(16 + name_sz);
        let size = voff + align8(value.len());
        let mut p = vec![0u8; size];
        p[0..4].copy_from_slice(&(size as i32).to_le_bytes());
        p[4..6].copy_from_slice(&(name_sz as i16).to_le_bytes());
        p[8..12].copy_from_slice(&nelem.to_le_bytes());
        p[12..16].copy_from_slice(&typ.to_le_bytes());
        p[16..16 + name.len()].copy_from_slice(name.as_bytes());
        p[voff..voff + value.len()].copy_from_slice(&value);
        out.extend_from_slice(&p);
    }
    out.extend_from_slice(&0i32.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdr_roundtrip() {
        let mut inner = NvList::default();
        inner.push("DSL_CRYPTO_SUITE", Value::U64(8)).push("DSL_CRYPTO_IV", Value::U8Array(vec![1, 2, 255]));
        let mut l = NvList::default();
        l.push("resume_object", Value::U64(5))
            .push("crypt_keydata", Value::List(inner))
            .push("flag", Value::Boolean)
            .push("s", Value::Str("abcde".into()));
        let mut b = encode_xdr(&l);
        assert_eq!(decode_xdr(&b).unwrap(), l);
        b.extend_from_slice(&[0; 4]);
        assert_eq!(decode_xdr(&b).unwrap(), l);
        b.push(1);
        assert!(decode_xdr(&b).is_err());
    }

    #[test]
    fn native_roundtrip() {
        let mut l = NvList::default();
        l.push("fromguid", Value::U64(1))
            .push("object", Value::U64(2))
            .push("toname", Value::Str("pool/fs@snap".into()))
            .push("embedok", Value::Boolean);
        let b = encode_native(&l);
        assert_eq!(decode_native(&b).unwrap(), l);
        for cut in 0..b.len() {
            assert!(decode_native(&b[..cut]).is_err());
        }
    }
}
