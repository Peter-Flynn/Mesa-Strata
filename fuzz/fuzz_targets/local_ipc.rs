#![no_main]
use libfuzzer_sys::fuzz_target;
use strata_proto::local::LOCAL_MSG;

// zfsd parses netd's messages and the client's halves parse each other's: every decoder
// must reject or round-trip exactly.
fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; LOCAL_MSG];
    let n = data.len().min(LOCAL_MSG);
    buf[..n].copy_from_slice(&data[..n]);
    if let Ok(r) = strata_proto::zipc::ZReq::decode(&buf) {
        assert_eq!(*r.encode().unwrap(), buf);
    }
    if let Ok(r) = strata_proto::zipc::ZResp::decode(&buf) {
        assert_eq!(*r.encode().unwrap(), buf);
    }
    if let Ok(r) = strata_client::ipc::CReq::decode(&buf) {
        assert_eq!(*r.encode().unwrap(), buf);
    }
    if let Ok(r) = strata_client::ipc::CResp::decode(&buf) {
        assert_eq!(*r.encode().unwrap(), buf);
    }
});
