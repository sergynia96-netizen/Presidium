//! Double Ratchet protocol for continuous forward secrecy.
//!
//! Implements the [Double Ratchet] protocol as used in Signal for continuous
//! key rotation. Each message advances the sending or receiving chain via
//! HMAC-based key derivation, and a DH ratchet is triggered whenever a new
//! ratchet public key is received from the peer.
//!
//! # Protocol Overview
//!
//! 1. **Initialization**: The ratchet is seeded with a 32-byte shared secret
//!    (typically the output of an X3DH handshake) and each party's initial
//!    X25519 ratchet key pair.
//!
//! 2. **Symmetric ratchet** (chain step): Each encryption/decryption advances
//!    the chain key via HMAC-SHA256, deriving a one-time message key and the
//!    next chain key.
//!
//! 3. **DH ratchet**: When a new ratchet public key is received from the peer,
//!    a Diffie-Hellman exchange is performed to derive a fresh root key and a
//!    new receiving chain. A new ephemeral sending key is then generated and
//!    a fresh sending chain is derived from the updated root key.
//!
//! # Example
//!
//! ```ignore
//! use presidium_crypto::ratchet::RatchetState;
//! use x25519_dalek::{StaticSecret, PublicKey};
//! use rand::rngs::OsRng;
//!
//! let shared_secret = [42u8; 32]; // from X3DH
//! let alice_sec = StaticSecret::random_from_rng(OsRng);
//! let bob_sec = StaticSecret::random_from_rng(OsRng);
//!
//! let mut alice = RatchetState::new(shared_secret, true, alice_sec, PublicKey::from(&bob_sec));
//! let mut bob = RatchetState::new(shared_secret, false, bob_sec, PublicKey::from(&alice_sec));
//!
//! let msg = alice.encrypt(b"Hello Bob").unwrap();
//! let plaintext = bob.decrypt(&msg).unwrap();
//! assert_eq!(plaintext, b"Hello Bob");
//! ```
//!
//! [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// Errors for ratchet operations.
#[derive(Error, Debug)]
pub enum RatchetError {
    /// The message header is malformed (too short, invalid key bytes).
    #[error("invalid message")]
    InvalidMessage,
    /// AEAD encryption failed (key material issue).
    #[error("encryption failed")]
    EncryptionError,
    /// AEAD decryption failed (wrong key, tampered ciphertext).
    #[error("decryption failed")]
    DecryptionError,
    /// Key derivation (HKDF or HMAC) failed.
    #[error("key derivation failed")]
    KdfError,
}

type HmacSha256 = Hmac<Sha256>;

/// Size of the `ChaCha20Poly1305` nonce (12 bytes).
const NONCE_SIZE: usize = 12;

/// HKDF info label for deriving the root key during a DH ratchet.
const RATCHET_ROOT_LABEL: &[u8] = b"Presidium-Ratchet-root";

/// HKDF info label for deriving a chain key during a DH ratchet.
const RATCHET_CHAIN_LABEL: &[u8] = b"Presidium-Ratchet-chain";

/// A message produced by the ratchet encrypt operation.
///
/// The `header` contains the sender's current ratchet public key (32 bytes)
/// followed by the message number (4 bytes, little-endian). The `ciphertext`
/// is the AEAD-encrypted plaintext (includes the 16-byte Poly1305 tag).
pub struct RatchetMessage {
    /// Ratchet header: ratchet public key (32 bytes) + message number (4 bytes).
    pub header: Vec<u8>,
    /// AEAD-encrypted ciphertext (plaintext + 16-byte Poly1305 tag).
    pub ciphertext: Vec<u8>,
}

/// Chain key for a sending or receiving chain.
///
/// Each step derives a message key (for AEAD encryption) and the next chain key
/// via HMAC-SHA256 with domain-separated labels (`0x01` for message key,
/// `0x02` for the next chain key), following the Signal spec convention.
#[derive(Clone)]
struct ChainKey([u8; 32]);

impl ChainKey {
    /// Advance the chain: derive a message key and the next chain key.
    ///
    /// Uses domain separation: label `0x01` for the message key, `0x02` for
    /// the next chain key.
    fn step(&self) -> Result<([u8; 32], ChainKey), RatchetError> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.0).map_err(|_| RatchetError::KdfError)?;
        mac.update(&[0x01]);
        let msg_key: [u8; 32] = mac.finalize().into_bytes().into();

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.0).map_err(|_| RatchetError::KdfError)?;
        mac.update(&[0x02]);
        let next_chain: [u8; 32] = mac.finalize().into_bytes().into();

        Ok((msg_key, ChainKey(next_chain)))
    }
}

/// Ratchet state for a single peer session.
///
/// Maintains the root key, sending/receiving chain keys, and DH ratchet keys.
/// The initiator (Alice) performs an initial DH ratchet before her first
/// encryption to derive the sending chain. The responder (Bob) triggers a
/// DH ratchet upon receiving the first message (which contains Alice's new
/// ratchet public key).
pub struct RatchetState {
    root_key: [u8; 32],
    sending_chain: Option<ChainKey>,
    receiving_chain: Option<ChainKey>,
    send_ratchet_key: Option<X25519StaticSecret>,
    recv_ratchet_key: Option<X25519PublicKey>,
    send_message_number: u32,
    recv_message_number: u32,
}

impl RatchetState {
    /// Initialize ratchet from a shared secret (output of X3DH).
    ///
    /// - `shared_secret`: 32-byte shared secret from the X3DH handshake.
    /// - `is_initiator`: `true` for Alice (sends first), `false` for Bob.
    /// - `our_key`: our initial X25519 ratchet secret key.
    /// - `their_key`: the peer's initial X25519 ratchet public key.
    ///
    /// Both parties start with no chains. The initiator derives a sending chain
    /// via DH ratchet on first [`encrypt`](Self::encrypt) call; the responder
    /// derives a receiving chain on first [`decrypt`](Self::decrypt) call.
    #[must_use]
    pub fn new(
        shared_secret: [u8; 32],
        _is_initiator: bool,
        our_key: X25519StaticSecret,
        their_key: X25519PublicKey,
    ) -> Self {
        RatchetState {
            root_key: shared_secret,
            sending_chain: None,
            receiving_chain: None,
            send_ratchet_key: Some(our_key),
            recv_ratchet_key: Some(their_key),
            send_message_number: 0,
            recv_message_number: 0,
        }
    }

    /// Encrypt plaintext, advancing the sending chain.
    ///
    /// On the first call (no sending chain), the initiator performs an initial
    /// DH ratchet to derive the sending chain. Subsequent calls simply advance
    /// the chain key.
    ///
    /// # Errors
    ///
    /// Returns [`RatchetError::EncryptionError`] if the initial DH ratchet
    /// cannot be performed or AEAD encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, RatchetError> {
        if self.sending_chain.is_none() {
            self.init_send_ratchet()?;
        }

        let chain = self
            .sending_chain
            .as_mut()
            .ok_or(RatchetError::EncryptionError)?;
        let (msg_key, next_chain) = chain.step()?;
        *chain = next_chain;

        let msg_number = self.send_message_number;
        self.send_message_number += 1;

        // Build header before encryption so it can be used as AEAD AAD.
        // This cryptographically binds the header (ratchet key + counter)
        // to the ciphertext, preventing undetected header tampering.
        let mut header = Vec::with_capacity(36);
        if let Some(ref key) = self.send_ratchet_key {
            header.extend_from_slice(X25519PublicKey::from(key).as_bytes());
        }
        header.extend_from_slice(&msg_number.to_le_bytes());

        let nonce = Self::make_nonce(msg_number);

        let cipher = ChaCha20Poly1305::new_from_slice(&msg_key)
            .map_err(|_| RatchetError::EncryptionError)?;
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| RatchetError::EncryptionError)?;

        Ok(RatchetMessage {
            header,
            ciphertext: ct,
        })
    }

    /// Decrypt a message, potentially performing a DH ratchet.
    ///
    /// If the message header contains a ratchet public key different from the
    /// one we have seen (or we have none), a DH ratchet is triggered:
    ///
    /// 1. DH(our current send key, their new key) → derive new root + receiving chain.
    /// 2. Generate a new ephemeral send key pair.
    /// 3. DH(new send key, their new key) → derive newer root + sending chain.
    ///
    /// # Errors
    ///
    /// - [`RatchetError::InvalidMessage`] if the header is too short.
    /// - [`RatchetError::DecryptionError`] if AEAD decryption fails.
    /// - [`RatchetError::KdfError`] if key derivation fails.
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>, RatchetError> {
        if message.header.len() < 36 {
            return Err(RatchetError::InvalidMessage);
        }

        let (their_ratchet_key_bytes, header_rest) = message.header.split_at(32);
        let msg_number_bytes: [u8; 4] = header_rest[..4]
            .try_into()
            .map_err(|_| RatchetError::InvalidMessage)?;
        let their_ratchet_key = X25519PublicKey::from(
            <[u8; 32]>::try_from(their_ratchet_key_bytes)
                .map_err(|_| RatchetError::InvalidMessage)?,
        );
        let msg_number = u32::from_le_bytes(msg_number_bytes);

        // If we have no receiving chain or ratchet key changed → DH ratchet
        let dh_ratchet_needed = match self.recv_ratchet_key {
            Some(ref pk) => pk.as_bytes() != their_ratchet_key.as_bytes(),
            None => true,
        };

        if dh_ratchet_needed {
            self.dh_ratchet(&their_ratchet_key)?;
        }

        // Advance the receiving chain — but do NOT commit until decrypt succeeds.
        // A corrupted/tampered packet must not permanently desynchronize the session.
        let chain = self
            .receiving_chain
            .as_mut()
            .ok_or(RatchetError::DecryptionError)?;
        let (msg_key, next_chain) = chain.step()?;

        let nonce = Self::make_nonce(msg_number);
        let cipher = ChaCha20Poly1305::new_from_slice(&msg_key)
            .map_err(|_| RatchetError::DecryptionError)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: message.ciphertext.as_slice(),
                    aad: &message.header,
                },
            )
            .map_err(|_| RatchetError::DecryptionError)?;

        // Only commit the chain advance after successful AEAD authentication.
        *chain = next_chain;

        self.recv_message_number = msg_number + 1;

        Ok(plaintext)
    }

    /// Initial DH ratchet for the initiator before first encrypt.
    ///
    /// Generates a new ratchet key pair and performs DH with the peer's known
    /// public key to derive a fresh root key and sending chain. The peer will
    /// perform the symmetric DH (same output due to DH commutativity) upon
    /// receiving the first message, deriving the matching receiving chain.
    fn init_send_ratchet(&mut self) -> Result<(), RatchetError> {
        let their_key = self
            .recv_ratchet_key
            .as_ref()
            .ok_or(RatchetError::KdfError)?;

        // Generate a new ratchet key (its public half goes in the header)
        let new_send_key = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dh_output = new_send_key.diffie_hellman(their_key);

        let kdf = Hkdf::<Sha256>::new(Some(&self.root_key), dh_output.as_bytes());
        let mut new_root = [0u8; 32];
        let mut chain_bytes = [0u8; 32];
        kdf.expand(RATCHET_ROOT_LABEL, &mut new_root)
            .map_err(|_| RatchetError::KdfError)?;
        kdf.expand(RATCHET_CHAIN_LABEL, &mut chain_bytes)
            .map_err(|_| RatchetError::KdfError)?;

        self.root_key = new_root;
        self.send_ratchet_key = Some(new_send_key);
        self.sending_chain = Some(ChainKey(chain_bytes));

        Ok(())
    }

    /// Perform a full DH ratchet step (triggered by receiving a new key).
    ///
    /// 1. DH(our current send key, their new key) → derive new root + receiving chain.
    /// 2. Generate new ephemeral send key pair.
    /// 3. DH(new send key, their new key) → derive newer root + sending chain.
    ///
    /// The two DH operations ensure that both parties derive matching chain keys
    /// because Diffie-Hellman is commutative: `DH(a, B) == DH(b, A)`.
    fn dh_ratchet(&mut self, their_new_key: &X25519PublicKey) -> Result<(), RatchetError> {
        // Step 1: Receiving side DH → derive receiving chain
        let our_key = self
            .send_ratchet_key
            .as_ref()
            .ok_or(RatchetError::KdfError)?;
        let dh_output = our_key.diffie_hellman(their_new_key);

        let kdf = Hkdf::<Sha256>::new(Some(&self.root_key), dh_output.as_bytes());
        let mut new_root = [0u8; 32];
        let mut recv_chain_bytes = [0u8; 32];
        kdf.expand(RATCHET_ROOT_LABEL, &mut new_root)
            .map_err(|_| RatchetError::KdfError)?;
        kdf.expand(RATCHET_CHAIN_LABEL, &mut recv_chain_bytes)
            .map_err(|_| RatchetError::KdfError)?;

        self.root_key = new_root;
        self.receiving_chain = Some(ChainKey(recv_chain_bytes));
        self.recv_ratchet_key = Some(*their_new_key);

        // Step 2: Generate new send key and derive sending chain
        let new_send_key = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dh_output2 = new_send_key.diffie_hellman(their_new_key);

        let kdf2 = Hkdf::<Sha256>::new(Some(&self.root_key), dh_output2.as_bytes());
        let mut newer_root = [0u8; 32];
        let mut send_chain_bytes = [0u8; 32];
        kdf2.expand(RATCHET_ROOT_LABEL, &mut newer_root)
            .map_err(|_| RatchetError::KdfError)?;
        kdf2.expand(RATCHET_CHAIN_LABEL, &mut send_chain_bytes)
            .map_err(|_| RatchetError::KdfError)?;

        self.root_key = newer_root;
        self.send_ratchet_key = Some(new_send_key);
        self.sending_chain = Some(ChainKey(send_chain_bytes));

        Ok(())
    }

    /// Construct a 12-byte nonce from a message counter.
    ///
    /// The counter occupies the first 4 bytes (little-endian), with the
    /// remaining 8 bytes set to zero. This is safe because the chain key
    /// changes for every message, guaranteeing unique (key, nonce) pairs.
    fn make_nonce(counter: u32) -> Nonce {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..4].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use rand::rngs::OsRng;

    /// Helper: create a paired ratchet state for Alice (initiator) and Bob (responder).
    fn init_pair() -> (RatchetState, RatchetState) {
        let shared_secret = [1u8; 32];
        let alice_sec = X25519StaticSecret::random_from_rng(OsRng);
        let alice_pub = X25519PublicKey::from(&alice_sec);
        let bob_sec = X25519StaticSecret::random_from_rng(OsRng);
        let bob_pub = X25519PublicKey::from(&bob_sec);

        let alice = RatchetState::new(shared_secret, true, alice_sec, bob_pub);
        let bob = RatchetState::new(shared_secret, false, bob_sec, alice_pub);
        (alice, bob)
    }

    #[test]
    fn basic_encrypt_decrypt() {
        let (mut alice, mut bob) = init_pair();
        let msg = b"Hello Bob";
        let encrypted = alice.encrypt(msg).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn multiple_sequential_messages() {
        let (mut alice, mut bob) = init_pair();
        for i in 0..10 {
            let msg = format!("Message {i}");
            let enc = alice.encrypt(msg.as_bytes()).unwrap();
            let dec = bob.decrypt(&enc).unwrap();
            assert_eq!(dec, msg.as_bytes());
        }
    }

    #[test]
    fn interleaved_conversation() {
        let (mut alice, mut bob) = init_pair();

        // Alice sends
        let enc1 = alice.encrypt(b"Hello").unwrap();
        let dec1 = bob.decrypt(&enc1).unwrap();
        assert_eq!(dec1, b"Hello");

        // Bob sends (triggers DH ratchet on Alice's side)
        let enc2 = bob.encrypt(b"Hi Alice").unwrap();
        let dec2 = alice.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"Hi Alice");

        // Alice sends again
        let enc3 = alice.encrypt(b"How are you?").unwrap();
        let dec3 = bob.decrypt(&enc3).unwrap();
        assert_eq!(dec3, b"How are you?");

        // Bob sends again
        let enc4 = bob.encrypt(b"Fine, thanks!").unwrap();
        let dec4 = alice.decrypt(&enc4).unwrap();
        assert_eq!(dec4, b"Fine, thanks!");
    }

    #[test]
    fn sequential_decrypt_after_interleaved() {
        let (mut alice, mut bob) = init_pair();

        // Alice sends two messages
        let msg1 = alice.encrypt(b"First").unwrap();
        let msg2 = alice.encrypt(b"Second").unwrap();

        // Bob must decrypt in order (simplified ratchet has no out-of-order support)
        let dec1 = bob.decrypt(&msg1).unwrap();
        assert_eq!(dec1, b"First");
        let dec2 = bob.decrypt(&msg2).unwrap();
        assert_eq!(dec2, b"Second");
    }

    #[test]
    fn long_conversation() {
        let (mut alice, mut bob) = init_pair();
        for i in 0..50 {
            let msg_a = format!("Alice msg {i}");
            let enc_a = alice.encrypt(msg_a.as_bytes()).unwrap();
            let dec_a = bob.decrypt(&enc_a).unwrap();
            assert_eq!(dec_a, msg_a.as_bytes());

            let msg_b = format!("Bob msg {i}");
            let enc_b = bob.encrypt(msg_b.as_bytes()).unwrap();
            let dec_b = alice.decrypt(&enc_b).unwrap();
            assert_eq!(dec_b, msg_b.as_bytes());
        }
    }

    #[test]
    fn empty_plaintext() {
        let (mut alice, mut bob) = init_pair();
        let enc = alice.encrypt(b"").unwrap();
        let dec = bob.decrypt(&enc).unwrap();
        assert_eq!(dec, b"");
    }

    #[test]
    fn large_plaintext() {
        let (mut alice, mut bob) = init_pair();
        let large = vec![0xABu8; 4096];
        let enc = alice.encrypt(&large).unwrap();
        let dec = bob.decrypt(&enc).unwrap();
        assert_eq!(dec, large);
    }

    #[test]
    fn different_shared_secrets_produce_different_keys() {
        let alice_sec = X25519StaticSecret::random_from_rng(OsRng);
        let bob_sec = X25519StaticSecret::random_from_rng(OsRng);
        let _alice_pub = X25519PublicKey::from(&alice_sec);
        let bob_pub = X25519PublicKey::from(&bob_sec);

        let mut alice1 = RatchetState::new([1u8; 32], true, alice_sec, bob_pub);
        let enc1 = alice1.encrypt(b"test").unwrap();

        let alice_sec2 = X25519StaticSecret::random_from_rng(OsRng);
        let bob_sec2 = X25519StaticSecret::random_from_rng(OsRng);
        let _alice_pub2 = X25519PublicKey::from(&alice_sec2);
        let bob_pub2 = X25519PublicKey::from(&bob_sec2);

        let mut alice2 = RatchetState::new([2u8; 32], true, alice_sec2, bob_pub2);
        let enc2 = alice2.encrypt(b"test").unwrap();

        // Same plaintext but different shared secrets → different ciphertexts
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut alice, mut bob) = init_pair();
        let mut enc = alice.encrypt(b"secret").unwrap();
        // Flip a byte in the ciphertext
        if let Some(byte) = enc.ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        let result = bob.decrypt(&enc);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_header_fails() {
        let (mut alice, mut bob) = init_pair();
        let mut enc = alice.encrypt(b"secret").unwrap();
        // Flip a byte in the ratchet key portion of the header
        if !enc.header.is_empty() {
            enc.header[0] ^= 0xFF;
        }
        let result = bob.decrypt(&enc);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_counter_fails() {
        let (mut alice, mut bob) = init_pair();
        let mut enc = alice.encrypt(b"secret").unwrap();
        // Modify the message counter in the header
        let counter_offset = 32; // ratchet key is first 32 bytes
        enc.header[counter_offset] ^= 0x01;
        let result = bob.decrypt(&enc);
        assert!(result.is_err());
    }

    #[test]
    fn too_short_header_fails() {
        let (mut alice, _bob) = init_pair();
        let short_msg = RatchetMessage {
            header: vec![0u8; 10], // too short (need 36 bytes)
            ciphertext: vec![0u8; 32],
        };
        let result = alice.decrypt(&short_msg);
        assert!(result.is_err());
    }

    /// Verify that a failed decrypt does NOT advance the receiving chain.
    /// A corrupted ciphertext must not permanently desynchronize the session.
    #[test]
    fn failed_decrypt_does_not_advance_chain() {
        let (mut alice, mut bob) = init_pair();

        // Alice sends two messages in sequence
        let msg1 = alice.encrypt(b"msg1").unwrap();
        let msg2 = alice.encrypt(b"msg2").unwrap();

        // Construct a tampered message: same header, corrupted ciphertext.
        // The header is used as AAD, so the tampered ciphertext is rejected
        // by AEAD authentication — but the chain key must NOT be advanced.
        let tampered_msg = RatchetMessage {
            header: msg1.header.clone(),
            ciphertext: {
                let mut ct = msg1.ciphertext.clone();
                ct[0] ^= 0xFF; // flip a byte
                ct
            },
        };
        let result = bob.decrypt(&tampered_msg);
        assert!(result.is_err(), "tampered ciphertext must fail");

        // The real msg1 must still decrypt correctly (chain was not advanced)
        let dec1 = bob.decrypt(&msg1).unwrap();
        assert_eq!(dec1, b"msg1");

        // msg2 must also decrypt correctly
        let dec2 = bob.decrypt(&msg2).unwrap();
        assert_eq!(dec2, b"msg2");
    }
}
