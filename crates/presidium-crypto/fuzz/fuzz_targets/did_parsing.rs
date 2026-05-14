#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if s.starts_with("did:presidium:") {
            // Should never panic on any input, even invalid base58
            let _ = presidium_crypto::identity::parse_did(s);
        }
    }
});
