#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(l) = strata_zstream::nvlist::decode_xdr(data) {
        assert_eq!(strata_zstream::nvlist::decode_xdr(&strata_zstream::nvlist::encode_xdr(&l)).unwrap(), l);
    }
    let _ = strata_zstream::nvlist::decode_native(data);
});
