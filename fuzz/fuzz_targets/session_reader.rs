#![no_main]
use libfuzzer_sys::fuzz_target;

// Plaintext frames → batches → messages, as netd and the client parse them after
// decryption.
fuzz_target!(|data: &[u8]| {
    let mut r = strata_proto::session::MsgReader::plain(std::io::Cursor::new(data.to_vec()));
    for _ in 0..64 {
        if r.recv().is_err() {
            break;
        }
    }
});
