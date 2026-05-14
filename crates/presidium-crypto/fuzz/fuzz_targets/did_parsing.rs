#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // parse_did should never panic on any input
        let _ = presidium_crypto::identity::parse_did(s);
    }
});
