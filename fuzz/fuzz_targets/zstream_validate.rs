#![no_main]
use libfuzzer_sys::fuzz_target;
use strata_zstream::{Expect, Validator};

// The first byte picks a split point so chunk boundaries vary; the second picks the
// expected base so both full and incremental paths run.
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = data[0] as usize;
    let fromguid = if data[1] & 1 == 0 { 0 } else { u64::from_le_bytes([data[1], 0, 0, 0, 0, 0, 0, 0]) };
    let body = &data[2..];
    let mut v = Validator::new(Expect { fromguid, toguid: None, allow_raw: data[1] & 2 != 0 });
    let mut out = Vec::new();
    let (a, b) = body.split_at(split.min(body.len()));
    if v.push(a, &mut out).is_ok() && v.push(b, &mut out).is_ok() {
        assert!(out.len() <= body.len());
        assert_eq!(&body[..out.len()], &out[..]);
        let _ = v.finish();
    }
});
