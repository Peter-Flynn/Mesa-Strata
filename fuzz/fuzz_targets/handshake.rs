#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<strata_proto::hs::Hs>(data);
    let _ = strata_proto::msg::decode(data);
});
