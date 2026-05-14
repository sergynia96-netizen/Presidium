#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to decrypt arbitrary bytes with a fixed password.
    // This should never panic — any input must either decrypt or return an error.
    let _ = presidium_crypto::vault::decrypt(data, "fuzz-password");
});
