//! `receive_resume_token` strings, as built by `get_receive_resume_token_impl` in
//! module/zfs/dsl_dataset.c: `1-<fletcher4 word 0 of the compressed bytes, hex>-<packed
//! length, hex>-<hex of the zlib-compressed native nvlist>`. When zlib can't shrink the
//! nvlist the kernel stores it uncompressed, in which case the two lengths are equal.

use std::io::{Read, Write};

use crate::fletcher::Fletcher4;
use crate::nvlist::{NvList, Value, decode_native, encode_native};
use crate::{StreamError, invalid};

const MAX_TOKEN: usize = 8192;
const MAX_PACKED: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeToken {
    pub fromguid: u64,
    pub toguid: u64,
    pub object: u64,
    pub offset: u64,
    pub bytes: u64,
    pub toname: String,
    pub largeblockok: bool,
    pub embedok: bool,
    pub compressok: bool,
    pub rawok: bool,
}

fn parse_hex_u64(s: &str) -> Result<u64, StreamError> {
    if s.is_empty() || s.len() > 16 {
        return invalid("bad token number");
    }
    u64::from_str_radix(s, 16).map_err(|_| StreamError::Invalid("bad token number".into()))
}

impl ResumeToken {
    pub fn decode(token: &str) -> Result<ResumeToken, StreamError> {
        if token.len() > MAX_TOKEN || !token.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') {
            return invalid("resume token has unexpected characters or length");
        }
        let mut parts = token.splitn(4, '-');
        let (Some(version), Some(cksum), Some(packed_len), Some(data)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return invalid("resume token has too few fields");
        };
        if version != "1" {
            return invalid("unsupported resume token version");
        }
        let cksum = parse_hex_u64(cksum)?;
        let packed_len = parse_hex_u64(packed_len)? as usize;
        if packed_len > MAX_PACKED || data.len() % 2 != 0 {
            return invalid("bad resume token lengths");
        }
        let compressed = hex::decode(data).map_err(|_| StreamError::Invalid("bad token hex".into()))?;
        if Fletcher4::of(&compressed).w[0] != cksum {
            return invalid("resume token checksum mismatch");
        }
        let packed = if compressed.len() == packed_len {
            compressed
        } else {
            let mut out = Vec::with_capacity(packed_len);
            flate2::read::ZlibDecoder::new(&compressed[..])
                .take(packed_len as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|_| StreamError::Invalid("resume token does not decompress".into()))?;
            if out.len() != packed_len {
                return invalid("resume token decompressed to the wrong length");
            }
            out
        };
        let nv = decode_native(&packed)?;
        for (name, _) in &nv.0 {
            if !matches!(
                name.as_str(),
                "fromguid"
                    | "object"
                    | "offset"
                    | "bytes"
                    | "toguid"
                    | "toname"
                    | "largeblockok"
                    | "embedok"
                    | "compressok"
                    | "rawok"
            ) {
                return invalid(format!("resume token field {name:?} is not supported"));
            }
        }
        let need = |n: &str| nv.u64(n).ok_or_else(|| StreamError::Invalid(format!("resume token lacks {n}")));
        let toname = match nv.get("toname") {
            Some(Value::Str(s)) => s.clone(),
            _ => return invalid("resume token lacks toname"),
        };
        Ok(ResumeToken {
            fromguid: nv.u64("fromguid").unwrap_or(0),
            toguid: need("toguid")?,
            object: need("object")?,
            offset: need("offset")?,
            bytes: nv.u64("bytes").unwrap_or(0),
            toname,
            largeblockok: nv.has("largeblockok"),
            embedok: nv.has("embedok"),
            compressok: nv.has("compressok"),
            rawok: nv.has("rawok"),
        })
    }

    pub fn encode(&self) -> String {
        let mut nv = NvList::default();
        if self.fromguid != 0 {
            nv.push("fromguid", Value::U64(self.fromguid));
        }
        nv.push("object", Value::U64(self.object))
            .push("offset", Value::U64(self.offset))
            .push("bytes", Value::U64(self.bytes))
            .push("toguid", Value::U64(self.toguid))
            .push("toname", Value::Str(self.toname.clone()));
        for (flag, name) in [
            (self.largeblockok, "largeblockok"),
            (self.embedok, "embedok"),
            (self.compressok, "compressok"),
            (self.rawok, "rawok"),
        ] {
            if flag {
                nv.push(name, Value::Boolean);
            }
        }
        let packed = encode_native(&nv);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        z.write_all(&packed).unwrap();
        let compressed = z.finish().unwrap();
        let cksum = Fletcher4::of(&compressed).w[0];
        format!("1-{cksum:x}-{:x}-{}", packed.len(), hex::encode(compressed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let t = ResumeToken {
            fromguid: 0x1234,
            toguid: 0xdead_beef,
            object: 17,
            offset: 131072,
            bytes: 999,
            toname: "rpool/home@strata_home_20261117T000000Z".into(),
            largeblockok: true,
            embedok: true,
            compressok: true,
            rawok: false,
        };
        let s = t.encode();
        assert_eq!(ResumeToken::decode(&s).unwrap(), t);
        let mut bad = s.clone().into_bytes();
        let last = bad.len() - 3;
        bad[last] = if bad[last] == b'0' { b'1' } else { b'0' };
        assert!(ResumeToken::decode(std::str::from_utf8(&bad).unwrap()).is_err());
        assert!(ResumeToken::decode("2-0-0-").is_err());
        assert!(ResumeToken::decode("1-x-0-00").is_err());
    }
}
