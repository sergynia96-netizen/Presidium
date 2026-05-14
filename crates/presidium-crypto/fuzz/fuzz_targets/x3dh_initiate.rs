#![no_main]

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use presidium_crypto::x3dh::{initiate, OneTimePreKey, PreKeyBundle, SignedPreKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

fuzz_target!(|data: &[u8]| {
    // Need at least 128 bytes: 32 (ik_a) + 32 (ek_a) + 32 (ik_b) + 32 (spk_b)
    if data.len() < 128 {
        return;
    }

    let ik_a_bytes: [u8; 32] = data[..32].try_into().unwrap_or([0u8; 32]);
    let ek_a_bytes: [u8; 32] = data[32..64].try_into().unwrap_or([0u8; 32]);
    let ik_b_bytes: [u8; 32] = data[64..96].try_into().unwrap_or([0u8; 32]);
    let spk_b_bytes: [u8; 32] = data[96..128].try_into().unwrap_or([0u8; 32]);

    let ik_a = SigningKey::from_bytes(&ik_a_bytes);
    let ek_a = X25519StaticSecret::from(ek_a_bytes);
    let ik_b = X25519PublicKey::from(ik_b_bytes);
    let spk_b = X25519PublicKey::from(spk_b_bytes);

    let bundle = PreKeyBundle {
        identity_key: ik_b,
        signed_pre_key: SignedPreKey { key: spk_b },
        one_time_pre_keys: vec![],
    };

    // Must not panic on any input — this is the key property being fuzzed
    let _ = initiate(&ik_a, &ek_a, &bundle);

    // Also test with a one-time prekey if we have enough bytes
    if data.len() >= 160 {
        let opk_b_bytes: [u8; 32] = data[128..160].try_into().unwrap_or([0u8; 32]);
        let opk_b = X25519PublicKey::from(opk_b_bytes);

        let bundle_with_opk = PreKeyBundle {
            identity_key: ik_b,
            signed_pre_key: SignedPreKey { key: spk_b },
            one_time_pre_keys: vec![OneTimePreKey { key: opk_b }],
        };

        let _ = initiate(&ik_a, &ek_a, &bundle_with_opk);
    }
});
