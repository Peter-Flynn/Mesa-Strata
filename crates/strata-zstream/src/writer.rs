//! Emits send streams in the exact on-wire format `dump_record` in dmu_send.c produces,
//! running checksums included. The fake ZFS sends with it and tests build streams with it.

use std::io::{self, Write};

use crate::fletcher::Fletcher4;
use crate::nvlist::{NvList, encode_xdr};
use crate::record::*;

#[derive(Clone, Debug)]
pub struct Begin {
    pub toguid: u64,
    pub fromguid: u64,
    pub toname: String,
    pub objset_type: u32,
    pub hdrtype: u64,
    pub features: u64,
    pub flags: u32,
    pub creation: u64,
    pub payload: Option<NvList>,
}

impl Begin {
    pub fn new(toguid: u64, fromguid: u64, toname: &str) -> Begin {
        Begin {
            toguid,
            fromguid,
            toname: toname.to_string(),
            objset_type: DMU_OST_ZFS,
            hdrtype: DMU_SUBSTREAM,
            features: FEATURE_EMBED_DATA | FEATURE_LARGE_BLOCKS | FEATURE_COMPRESSED,
            flags: DRR_FLAG_FREERECORDS,
            creation: 0,
            payload: None,
        }
    }
}

pub struct StreamWriter<W: Write> {
    w: W,
    ck: Fletcher4,
    toguid: u64,
}

impl<W: Write> StreamWriter<W> {
    pub fn begin(w: W, b: &Begin) -> io::Result<StreamWriter<W>> {
        let mut h = [0u8; HEADER];
        put_u32(&mut h, 0, DRR_BEGIN);
        put_u64(&mut h, 8, DMU_BACKUP_MAGIC);
        put_u64(&mut h, 16, versioninfo(b.hdrtype, b.features));
        put_u64(&mut h, 24, b.creation);
        put_u32(&mut h, 32, b.objset_type);
        put_u32(&mut h, 36, b.flags);
        put_u64(&mut h, 40, b.toguid);
        put_u64(&mut h, 48, b.fromguid);
        assert!(b.toname.len() < MAXNAMELEN);
        h[56..56 + b.toname.len()].copy_from_slice(b.toname.as_bytes());
        let mut payload = b.payload.as_ref().map(encode_xdr).unwrap_or_default();
        payload.resize(payload.len().div_ceil(8) * 8, 0);
        put_u32(&mut h, 4, payload.len() as u32);
        let mut sw = StreamWriter { w, ck: Fletcher4::default(), toguid: b.toguid };
        sw.ck.update(&h);
        sw.ck.update(&payload);
        sw.w.write_all(&h)?;
        sw.w.write_all(&payload)?;
        Ok(sw)
    }

    fn record(&mut self, mut h: [u8; HEADER], payload: &[u8]) -> io::Result<()> {
        self.ck.update(&h[..CKSUM_OFF]);
        h[CKSUM_OFF..].copy_from_slice(&self.ck.to_bytes());
        self.ck.update(&h[CKSUM_OFF..]);
        self.ck.update(payload);
        self.w.write_all(&h)?;
        self.w.write_all(payload)
    }

    pub fn object(&mut self, object: u64, blksz: u32, bonus: &[u8]) -> io::Result<()> {
        let mut h = [0u8; HEADER];
        put_u32(&mut h, 0, DRR_OBJECT);
        put_u64(&mut h, 8, object);
        put_u32(&mut h, 16, DMU_OT_PLAIN_FILE_CONTENTS);
        put_u32(&mut h, 24, blksz);
        put_u32(&mut h, 28, bonus.len() as u32);
        h[34] = 1;
        put_u64(&mut h, 40, self.toguid);
        let mut p = bonus.to_vec();
        p.resize(bonus.len().div_ceil(8) * 8, 0);
        self.record(h, &p)
    }

    pub fn write(&mut self, object: u64, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut h = [0u8; HEADER];
        put_u32(&mut h, 0, DRR_WRITE);
        put_u64(&mut h, 8, object);
        put_u32(&mut h, 16, DMU_OT_PLAIN_FILE_CONTENTS);
        put_u64(&mut h, 24, offset);
        put_u64(&mut h, 32, data.len() as u64);
        put_u64(&mut h, 40, self.toguid);
        self.record(h, data)
    }

    pub fn free(&mut self, object: u64, offset: u64, length: u64) -> io::Result<()> {
        let mut h = [0u8; HEADER];
        put_u32(&mut h, 0, DRR_FREE);
        put_u64(&mut h, 8, object);
        put_u64(&mut h, 16, offset);
        put_u64(&mut h, 24, length);
        put_u64(&mut h, 32, self.toguid);
        self.record(h, &[])
    }

    pub fn freeobjects(&mut self, first: u64, num: u64) -> io::Result<()> {
        let mut h = [0u8; HEADER];
        put_u32(&mut h, 0, DRR_FREEOBJECTS);
        put_u64(&mut h, 8, first);
        put_u64(&mut h, 16, num);
        put_u64(&mut h, 24, self.toguid);
        self.record(h, &[])
    }

    pub fn end(mut self) -> io::Result<W> {
        let mut h = [0u8; HEADER];
        put_u32(&mut h, 0, DRR_END);
        h[8..40].copy_from_slice(&self.ck.to_bytes());
        put_u64(&mut h, 40, self.toguid);
        self.record(h, &[])?;
        self.w.flush()?;
        Ok(self.w)
    }
}
