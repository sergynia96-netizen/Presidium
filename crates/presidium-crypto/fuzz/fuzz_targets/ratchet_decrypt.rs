#![no_main]
use libfuzzer_sys::fuzz_target;
use presidium_crypto::ratchet::{RatchetMessage, RatchetState};
use x25519_dalek::{PublicKey, StaticSecret};

fuzz_target!(|data: &[u8]| {
    // Need at least 68 bytes: 32 (their_pub) + 36 (header) + arbitrary ciphertext
    if data.len() < 68 {
        return;
    }

    let their_pub_bytes: [u8; 32] = match <[u8; 32]>::try_from(&data[..32]) {
        Ok(b) => b,
        Err(_) => return,
    };
    let their_pub = PublicKey::from(their_pub_bytes);

    let shared = [0u8; 32];
    let our_key = StaticSecret::from([0u8; 32]);
    let mut state = RatchetState::new(shared, false, our_key, their_pub);

    let header_len = 36;
    let msg = RatchetMessage {
        header: data[32..32 + header_len].to_vec(),
        ciphertext: data[32 + header_len..].to_vec(),
    };

    // Must not panic on any input
    let _ = state.decrypt(&msg);
});
