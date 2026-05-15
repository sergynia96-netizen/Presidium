//! Extended Triple Diffie-Hellman (X3DH) key agreement.
//!
//! Implements the X3DH protocol ([Signal specification][x3dh]) for asynchronous
//! key agreement between two parties (Alice and Bob). Alice uses Bob's published
//! prekey bundle to derive a shared secret without online interaction.
//!
//! The protocol performs up to four Diffie-Hellman exchanges:
//!
//! 1. **DH1**: Alice's identity key with Bob's signed prekey.
//! 2. **DH2**: Alice's ephemeral key with Bob's identity key.
//! 3. **DH3**: Alice's ephemeral key with Bob's signed prekey.
//! 4. **DH4** (optional): Alice's ephemeral key with a one-time prekey.
//!
//! The concatenated DH outputs are fed into HKDF-SHA256 with the info string
//! `"Presidium-X3DH-v1"` to produce the final 256-bit shared secret.
//!
//! Ed25519 keys are converted to X25519 via standard Montgomery conversions:
//! - Secret: `SHA-512(seed)[0..32]` (same scalar used internally by Ed25519 signing).
//! - Public: Edwards-to-Montgomery point conversion.
//!
//! [x3dh]: https://signal.org/docs/specifications/x3dh/
//!
//! # Example
//!
//! ```ignore
//! use ed25519_dalek::SigningKey;
//! use presidium_crypto::x3dh::{initiate, respond, PreKeyBundle, SignedPreKey, OneTimePreKey};
//! use rand::rngs::OsRng;
//! use x25519_dalek::{StaticSecret as X25519StaticSecret, PublicKey as X25519PublicKey};
//!
//! // Bob generates long-term and prekeys
//! let bob_sk = SigningKey::generate(&mut OsRng);
//! let bob_spk = X25519StaticSecret::random_from_rng(OsRng);
//! let bob_opk = X25519StaticSecret::random_from_rng(OsRng);
//!
//! let bundle = PreKeyBundle {
//!     identity_key: ed25519_to_x25519(bob_sk.verifying_key()).unwrap(),
//!     signed_pre_key: SignedPreKey { key: X25519PublicKey::from(&bob_spk) },
//!     one_time_pre_keys: vec![OneTimePreKey { key: X25519PublicKey::from(&bob_opk) }],
//! };
//!
//! // Alice initiates
//! let alice_sk = SigningKey::generate(&mut OsRng);
//! let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
//! let (shared, ek_a) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();
//!
//! // Bob responds
//! let bob_shared = respond(&bob_sk, &bob_spk, Some(&bob_opk),
//!     alice_sk.verifying_key(), &ek_a).unwrap();
//!
//! assert_eq!(shared, bob_shared);
//! ```

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// HKDF info string for X3DH shared secret derivation.
const X3DH_INFO: &[u8] = b"Presidium-X3DH-v1";

/// Errors that can occur during X3DH operations.
#[derive(Error, Debug)]
pub enum X3DHError {
    /// The Ed25519 public key could not be converted to an X25519 public key.
    ///
    /// This happens when the point is of low order (e.g., the identity element),
    /// which should never occur for properly generated Ed25519 keys.
    #[error("invalid Ed25519 public key: cannot convert to X25519")]
    InvalidPublicKey,
    /// HKDF expansion failed unexpectedly.
    #[error("HKDF expansion failed")]
    HkdfError,
}

/// A prekey bundle published by a user (Bob).
///
/// Contains the long-term identity key, a signed prekey (for forward secrecy),
/// and a list of one-time prekeys (for future secrecy).
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// The X25519 public key derived from the user's long-term Ed25519 identity key.
    pub identity_key: X25519PublicKey,
    /// The signed prekey — rotated periodically for forward secrecy.
    pub signed_pre_key: SignedPreKey,
    /// One-time prekeys — each is used only once, providing future secrecy.
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

/// A signed prekey belonging to a user's prekey bundle.
///
/// In a full implementation, this would carry a signature from the identity key.
/// For now, the signature verification is deferred to the protocol layer.
#[derive(Clone, Debug)]
pub struct SignedPreKey {
    /// The X25519 public key of the signed prekey.
    pub key: X25519PublicKey,
}

/// A one-time prekey belonging to a user's prekey bundle.
///
/// Each one-time prekey is used for at most one X3DH session.
#[derive(Clone, Debug)]
pub struct OneTimePreKey {
    /// The X25519 public key of the one-time prekey.
    pub key: X25519PublicKey,
}

/// Perform the X3DH initiation (Alice's side).
///
/// Given Alice's long-term identity key, an ephemeral X25519 key, and Bob's
/// prekey bundle, compute the shared secret. Returns the 32-byte shared secret
/// and the ephemeral public key (which must be sent to Bob).
///
/// If the bundle contains at least one one-time prekey, the first one is used
/// for the DH4 exchange. Otherwise, DH4 is skipped (the protocol still
/// provides security through DH1–DH3).
///
/// # Errors
///
/// Returns [`X3DHError::InvalidPublicKey`] if Bob's identity key (derived from
/// his Ed25519 public key) is not a valid X25519 public key.
pub fn initiate(
    our_identity_secret: &SigningKey,
    our_ephemeral_secret: &X25519StaticSecret,
    bundle: &PreKeyBundle,
) -> Result<([u8; 32], X25519PublicKey), X3DHError> {
    let ik_a = ed25519_to_x25519_static(our_identity_secret);
    let ek_a = our_ephemeral_secret;
    let ik_b = bundle.identity_key;
    let spk_b = bundle.signed_pre_key.key;

    // DH1 = IK_A · SPK_B
    let dh1 = ik_a.diffie_hellman(&spk_b);
    // DH2 = EK_A · IK_B
    let dh2 = ek_a.diffie_hellman(&ik_b);
    // DH3 = EK_A · SPK_B
    let dh3 = ek_a.diffie_hellman(&spk_b);

    // DH4 = EK_A · OPK_B (only if a one-time prekey is available)
    let dh4 = bundle
        .one_time_pre_keys
        .first()
        .map(|opk| ek_a.diffie_hellman(&opk.key));

    // Concatenate: DH1 || DH2 || DH3 [|| DH4]
    let shared_secret = derive_shared_secret(&dh1, &dh2, &dh3, dh4.as_ref())?;

    let ek_a_public = X25519PublicKey::from(ek_a);

    Ok((shared_secret, ek_a_public))
}

/// Perform the X3DH response (Bob's side).
///
/// Given Bob's long-term identity key, signed prekey, optional one-time prekey,
/// Alice's identity public key, and Alice's ephemeral public key, compute the
/// same shared secret that Alice derived.
///
/// The `our_one_time_pre_secret` parameter must be `Some` if the one-time prekey
/// was consumed during Alice's initiation, and `None` otherwise. A mismatch
/// will result in a different shared secret (and therefore failed communication).
///
/// # Errors
///
/// Returns [`X3DHError::InvalidPublicKey`] if Alice's identity key cannot be
/// converted from Ed25519 to X25519.
pub fn respond(
    our_identity_secret: &SigningKey,
    our_signed_pre_secret: &X25519StaticSecret,
    our_one_time_pre_secret: Option<&X25519StaticSecret>,
    their_identity_key: VerifyingKey,
    their_ephemeral_key: &X25519PublicKey,
) -> Result<[u8; 32], X3DHError> {
    let ik_b = ed25519_to_x25519_static(our_identity_secret);
    let spk_b = our_signed_pre_secret;
    let ik_a = ed25519_public_to_x25519(their_identity_key)?;
    let ek_a = their_ephemeral_key;

    // DH1 = SPK_B · IK_A
    let dh1 = spk_b.diffie_hellman(&ik_a);
    // DH2 = IK_B · EK_A
    let dh2 = ik_b.diffie_hellman(ek_a);
    // DH3 = SPK_B · EK_A
    let dh3 = spk_b.diffie_hellman(ek_a);

    // DH4 = OPK_B · EK_A (only if a one-time prekey was used)
    let dh4 = our_one_time_pre_secret.map(|opk_b| opk_b.diffie_hellman(ek_a));

    let shared_secret = derive_shared_secret(&dh1, &dh2, &dh3, dh4.as_ref())?;

    Ok(shared_secret)
}

/// Convert an Ed25519 signing key (seed) to an X25519 static secret.
///
/// The Ed25519 signing key stores a 32-byte seed. The actual scalar used in
/// Ed25519 signing is `SHA-512(seed)[0..32]`, which happens to also be the
/// correct X25519 scalar (after clamping, which `x25519-dalek` applies
/// internally during Diffie-Hellman).
///
/// The intermediate hash output is zeroized before returning.
#[must_use]
pub fn ed25519_to_x25519_static(secret: &SigningKey) -> X25519StaticSecret {
    let mut hasher = Sha512::new();
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&result[..32]);
    // Zeroize the full 64-byte hash output (contains the scalar in the first 32 bytes)
    let mut full_hash = [0u8; 64];
    full_hash.copy_from_slice(&result);
    full_hash.zeroize();
    X25519StaticSecret::from(scalar_bytes)
}

/// Convert an Ed25519 verifying (public) key to an X25519 public key.
///
/// Decompresses the Edwards-Y point and converts it to Montgomery form.
/// This is the standard conversion specified in RFC 7748.
///
/// # Errors
///
/// Returns [`X3DHError::InvalidPublicKey`] if the compressed point does not
/// represent a valid Edwards curve point (e.g., it is the identity element
/// or a low-order point).
pub fn ed25519_public_to_x25519(public: VerifyingKey) -> Result<X25519PublicKey, X3DHError> {
    let compressed = CompressedEdwardsY::from_slice(&public.to_bytes())
        .map_err(|_| X3DHError::InvalidPublicKey)?;
    let edwards_point = compressed.decompress().ok_or(X3DHError::InvalidPublicKey)?;
    let montgomery_point = edwards_point.to_montgomery();
    Ok(X25519PublicKey::from(montgomery_point.to_bytes()))
}

/// Derive the final X3DH shared secret from the four DH outputs using HKDF-SHA256.
///
/// Concatenates `DH1 || DH2 || DH3 [|| DH4]` and expands via HKDF with the
/// `"Presidium-X3DH-v1"` info string to produce a 32-byte shared secret.
fn derive_shared_secret(
    dh1: &x25519_dalek::SharedSecret,
    dh2: &x25519_dalek::SharedSecret,
    dh3: &x25519_dalek::SharedSecret,
    dh4: Option<&x25519_dalek::SharedSecret>,
) -> Result<[u8; 32], X3DHError> {
    let mut shared_input = Vec::with_capacity(128);
    shared_input.extend_from_slice(dh1.as_bytes());
    shared_input.extend_from_slice(dh2.as_bytes());
    shared_input.extend_from_slice(dh3.as_bytes());
    if let Some(dh4_val) = dh4 {
        shared_input.extend_from_slice(dh4_val.as_bytes());
    }

    let hkdf = Hkdf::<Sha256>::new(None, &shared_input);
    let mut shared_secret = [0u8; 32];
    hkdf.expand(X3DH_INFO, &mut shared_secret)
        .map_err(|_| X3DHError::HkdfError)?;

    // Zeroize the intermediate DH concatenation
    shared_input.zeroize();

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::similar_names)]
    use super::*;
    use rand::rngs::OsRng;

    /// Helper: generate a fresh X25519 keypair for testing.
    fn gen_x25519() -> (X25519StaticSecret, X25519PublicKey) {
        let secret = X25519StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        (secret, public)
    }

    /// Helper: generate a fresh Ed25519 signing key pair for testing.
    fn gen_ed25519() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Helper: build a prekey bundle from Bob's keys.
    fn make_bundle(
        bob_signing: &SigningKey,
        spk_public: X25519PublicKey,
        opk_public: Option<X25519PublicKey>,
    ) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: ed25519_public_to_x25519(bob_signing.verifying_key()).unwrap(),
            signed_pre_key: SignedPreKey { key: spk_public },
            one_time_pre_keys: opk_public
                .map(|k| vec![OneTimePreKey { key: k }])
                .unwrap_or_default(),
        }
    }

    #[test]
    fn basic_handshake_with_one_time_prekey() {
        let alice_sk = gen_ed25519();
        let bob_sk = gen_ed25519();

        let (bob_spk, bob_spk_pub) = gen_x25519();
        let (bob_opk, bob_opk_pub) = gen_x25519();

        let bundle = make_bundle(&bob_sk, bob_spk_pub, Some(bob_opk_pub));
        let alice_eph = X25519StaticSecret::random_from_rng(OsRng);

        let (alice_shared, alice_eph_pub) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();

        let bob_shared = respond(
            &bob_sk,
            &bob_spk,
            Some(&bob_opk),
            alice_sk.verifying_key(),
            &alice_eph_pub,
        )
        .unwrap();

        assert_eq!(alice_shared, bob_shared, "shared secrets must match");
    }

    #[test]
    fn handshake_no_one_time_prekey() {
        let alice_sk = gen_ed25519();
        let bob_sk = gen_ed25519();

        let (bob_spk, bob_spk_pub) = gen_x25519();

        let bundle = make_bundle(&bob_sk, bob_spk_pub, None);
        let alice_eph = X25519StaticSecret::random_from_rng(OsRng);

        let (alice_shared, alice_eph_pub) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();

        let bob_shared = respond(
            &bob_sk,
            &bob_spk,
            None,
            alice_sk.verifying_key(),
            &alice_eph_pub,
        )
        .unwrap();

        assert_eq!(
            alice_shared, bob_shared,
            "shared secrets must match without OPK"
        );
    }

    #[test]
    fn different_alices_produce_different_secrets() {
        let alice_sk = gen_ed25519();
        let carol_sk = gen_ed25519();
        let bob_sk = gen_ed25519();

        let (_bob_spk, bob_spk_pub) = gen_x25519();
        let (_bob_opk, bob_opk_pub) = gen_x25519();

        let bundle = make_bundle(&bob_sk, bob_spk_pub, Some(bob_opk_pub));

        let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
        let (alice_shared, _) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();

        let carol_eph = X25519StaticSecret::random_from_rng(OsRng);
        let (carol_shared, _) = initiate(&carol_sk, &carol_eph, &bundle).unwrap();

        assert_ne!(
            alice_shared, carol_shared,
            "different initiators must produce different shared secrets"
        );
    }

    #[test]
    fn different_bobs_produce_different_secrets() {
        let alice_sk = gen_ed25519();
        let bob_sk = gen_ed25519();
        let dave_sk = gen_ed25519();

        let (_bob_spk, bob_spk_pub) = gen_x25519();
        let (_bob_opk, bob_opk_pub) = gen_x25519();
        let bundle_bob = make_bundle(&bob_sk, bob_spk_pub, Some(bob_opk_pub));

        let (_dave_spk, dave_spk_pub) = gen_x25519();
        let (_dave_opk, dave_opk_pub) = gen_x25519();
        let bundle_dave = make_bundle(&dave_sk, dave_spk_pub, Some(dave_opk_pub));

        let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
        let (secret_bob, _) = initiate(&alice_sk, &alice_eph, &bundle_bob).unwrap();

        let alice_eph2 = X25519StaticSecret::random_from_rng(OsRng);
        let (secret_dave, _) = initiate(&alice_sk, &alice_eph2, &bundle_dave).unwrap();

        assert_ne!(secret_bob, secret_dave);
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let alice_sk = gen_ed25519();
        let bob_sk = gen_ed25519();
        let (_bob_spk, bob_spk_pub) = gen_x25519();
        let bundle = make_bundle(&bob_sk, bob_spk_pub, None);

        let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
        let (shared, _) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();
        assert_eq!(shared.len(), 32);
    }

    #[test]
    fn ed25519_public_to_x25519_roundtrip_consistency() {
        let sk = gen_ed25519();
        let vk = sk.verifying_key();

        // Converting the public key twice should give the same result
        let x1 = ed25519_public_to_x25519(vk).unwrap();
        let x2 = ed25519_public_to_x25519(vk).unwrap();
        assert_eq!(x1.as_bytes(), x2.as_bytes());
    }

    #[test]
    fn ed25519_to_x25519_static_dh_consistency() {
        // Two conversions of the same secret should yield the same DH result
        let sk = gen_ed25519();
        let secret1 = ed25519_to_x25519_static(&sk);
        let secret2 = ed25519_to_x25519_static(&sk);

        let public = ed25519_public_to_x25519(sk.verifying_key()).unwrap();
        let dh1 = secret1.diffie_hellman(&public);
        let dh2 = secret2.diffie_hellman(&public);
        assert_eq!(dh1.as_bytes(), dh2.as_bytes());
    }

    #[test]
    fn multiple_sessions_same_bundle() {
        let alice_sk = gen_ed25519();
        let bob_sk = gen_ed25519();
        let (bob_spk, bob_spk_pub) = gen_x25519();
        let (bob_opk, bob_opk_pub) = gen_x25519();

        let bundle = make_bundle(&bob_sk, bob_spk_pub, Some(bob_opk_pub));

        // First session
        let alice_eph1 = X25519StaticSecret::random_from_rng(OsRng);
        let (secret1, ek1) = initiate(&alice_sk, &alice_eph1, &bundle).unwrap();
        let bob_secret1 = respond(
            &bob_sk,
            &bob_spk,
            Some(&bob_opk),
            alice_sk.verifying_key(),
            &ek1,
        )
        .unwrap();
        assert_eq!(secret1, bob_secret1);

        // Second session with same bundle (different ephemeral)
        let alice_eph2 = X25519StaticSecret::random_from_rng(OsRng);
        let (secret2, ek2) = initiate(&alice_sk, &alice_eph2, &bundle).unwrap();
        let bob_secret2 = respond(
            &bob_sk,
            &bob_spk,
            Some(&bob_opk),
            alice_sk.verifying_key(),
            &ek2,
        )
        .unwrap();
        assert_eq!(secret2, bob_secret2);

        // The two sessions must have different shared secrets
        assert_ne!(secret1, secret2);
    }
}
