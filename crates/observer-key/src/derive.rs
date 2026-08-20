//! Additive ed25519 child derivation, ported byte-exact from summit's
//! `types/src/ext_private_key.rs` (itself from
//! <https://github.com/daltoncoder/commonware-ed25519-child-derivation-poc>).
//!
//! Private side: expand the master seed the standard ed25519 way (SHA-512,
//! clamp), add a public tweak `t = H(tag || master_pub || namespace || path)`
//! to the master scalar, and hash a fresh nonce prefix so sibling children
//! never share nonces. Public side: `child_pub = master_pub + t·G`, computable
//! from public data alone, verifiable with stock ed25519.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

// Domain tags shared with summit; changing either breaks parent/observer
// key agreement across the repo boundary.
const DERIVE_TAG: &[u8] = b"ed25519-additive-derive/tweak/v1";
const PREFIX_TAG: &[u8] = b"ed25519-additive-derive/prefix/v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeriveError {
    #[error("master public key is not a valid ed25519 point")]
    InvalidMasterKey,
}

fn observer_path(index: u32) -> Vec<u8> {
    format!("m/seismic/observer/{index}").into_bytes()
}

/// Standard ed25519 seed expansion: SHA-512 of the seed, clamp the low 32
/// bytes into the scalar, keep the high 32 bytes as the nonce prefix.
fn expand_seed(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h = Sha512::digest(seed);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let a = Scalar::from_bytes_mod_order(a_bytes);
    a_bytes.zeroize();
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    (a, prefix)
}

fn compute_tweak(master_pub: &[u8; 32], namespace: &[u8], path: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(DERIVE_TAG);
    h.update(master_pub);
    // Length-prefix the namespace so namespace/path boundaries can't collide
    // (u64-LE, matching summit exactly).
    h.update((namespace.len() as u64).to_le_bytes());
    h.update(namespace);
    h.update(path);
    let out: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&out)
}

/// The master public key for a node seed (clamped scalar times the base
/// point — identical bytes to what summit prints for `node_key.pem`). Lets
/// the parent compute its verification key and drop the seed.
pub fn master_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let (a, _prefix) = expand_seed(seed);
    (a * ED25519_BASEPOINT_POINT).compress().0
}

/// A derived child signer: the tweaked scalar plus a child-specific nonce
/// prefix. The key is a raw scalar (not a seed), so signing is implemented
/// manually — deterministic ed25519 over the raw message.
pub struct ObserverSigner {
    scalar: Scalar,
    prefix: [u8; 32],
    public: [u8; 32],
}

impl Drop for ObserverSigner {
    fn drop(&mut self) {
        self.scalar.zeroize();
        self.prefix.zeroize();
    }
}

impl std::fmt::Debug for ObserverSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObserverSigner")
            .field("public", &hex::encode(self.public))
            .field("scalar", &"<redacted>")
            .field("prefix", &"<redacted>")
            .finish()
    }
}

impl ObserverSigner {
    /// Derive the child signer at `index` from the master seed and the
    /// deployment namespace. Byte-exact to summit's
    /// `ExtPrivateKey::derive_child_signer`.
    pub fn derive(master_seed: &[u8; 32], namespace: &[u8], index: u32) -> Self {
        let path = observer_path(index);
        let (a, mut master_prefix) = expand_seed(master_seed);
        let master_pub = (a * ED25519_BASEPOINT_POINT).compress().0;
        let t = compute_tweak(&master_pub, namespace, &path);
        let scalar = a + t;

        let mut h = Sha512::new();
        h.update(PREFIX_TAG);
        h.update(master_prefix);
        h.update(t.as_bytes());
        let out: [u8; 64] = h.finalize().into();
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&out[..32]);
        master_prefix.zeroize();

        let public = (scalar * ED25519_BASEPOINT_POINT).compress().0;
        Self {
            scalar,
            prefix,
            public,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Deterministic ed25519 with the child scalar and prefix, over the raw
    /// message. Verifies under [`derive_child_public`]'s output with stock
    /// ed25519 verification.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut hr = Sha512::new();
        hr.update(self.prefix);
        hr.update(message);
        let r_bytes: [u8; 64] = hr.finalize().into();
        let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

        let r_point = (r * ED25519_BASEPOINT_POINT).compress();

        let mut hk = Sha512::new();
        hk.update(r_point.as_bytes());
        hk.update(self.public);
        hk.update(message);
        let k_bytes: [u8; 64] = hk.finalize().into();
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        let s = r + k * self.scalar;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r_point.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        sig
    }
}

/// Public counterpart of [`ObserverSigner::derive`]: `master_pub + t·G`,
/// from public data alone. This is what the parent custodian evaluates to
/// check that a fetch request was signed by a child of its own node key.
pub fn derive_child_public(
    master_public: &[u8; 32],
    namespace: &[u8],
    index: u32,
) -> Result<[u8; 32], DeriveError> {
    let a_point = CompressedEdwardsY(*master_public)
        .decompress()
        .ok_or(DeriveError::InvalidMasterKey)?;
    let t = compute_tweak(master_public, namespace, &observer_path(index));
    Ok((a_point + t * ED25519_BASEPOINT_POINT).compress().0)
}

/// Stock ed25519 verification (strict), false on any malformed input.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    key.verify_strict(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors generated from summit's `ExtPrivateKey` (seed [1u8; 32],
    // namespace b"golden-namespace"). Regenerate with a throwaway test in
    // summit's types/src/ext_private_key.rs if the scheme ever changes.
    const GOLDEN_SEED: [u8; 32] = [1u8; 32];
    const GOLDEN_NAMESPACE: &[u8] = b"golden-namespace";
    const GOLDEN_MASTER_PUB: &str =
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const GOLDEN_CHILD_PUB_0: &str =
        "9da2a015748d0c61ff8a34290a4d83707c9373f075b3df55b80256f3042e0c02";
    const GOLDEN_CHILD_PUB_7: &str =
        "7a71326f1863879929fe42be57daddabe8ca1548d1f2afdb707f39880d56071d";
    const GOLDEN_CHILD_PUB_MAX: &str =
        "f8db8756bb3df9c4c279cc0b2cf9317ea0ab8204ae72b7702af3a2f80a89bd13";
    // summit: child_7.sign(b"", b"golden message") — union_unique with an
    // empty namespace prepends the single varint byte 0x00, so this pins the
    // child *prefix* derivation (the deterministic nonce), not just the
    // scalar.
    const GOLDEN_SIG_7: &str = "695687e46c879f4fff9a00122e68f294f7d6e017ea01e6e2a02cd3f2cdd4ac4a23369ca30b4f11d083d25f7507d511a710ed52fe516132b9530788d9df3b900b";
    const GOLDEN_SIG_7_MESSAGE: &[u8] = b"\x00golden message";

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn golden_master_public() {
        assert_eq!(
            master_public_from_seed(&GOLDEN_SEED),
            hex32(GOLDEN_MASTER_PUB)
        );
    }

    #[test]
    fn golden_child_publics_match_summit() {
        for (index, expected) in [
            (0u32, GOLDEN_CHILD_PUB_0),
            (7, GOLDEN_CHILD_PUB_7),
            (u32::MAX, GOLDEN_CHILD_PUB_MAX),
        ] {
            let signer = ObserverSigner::derive(&GOLDEN_SEED, GOLDEN_NAMESPACE, index);
            assert_eq!(signer.public_key(), hex32(expected), "signer at {index}");
            let derived =
                derive_child_public(&hex32(GOLDEN_MASTER_PUB), GOLDEN_NAMESPACE, index).unwrap();
            assert_eq!(derived, hex32(expected), "public derivation at {index}");
        }
    }

    #[test]
    fn golden_signature_matches_summit() {
        let signer = ObserverSigner::derive(&GOLDEN_SEED, GOLDEN_NAMESPACE, 7);
        let sig = signer.sign(GOLDEN_SIG_7_MESSAGE);
        assert_eq!(hex::encode(sig), GOLDEN_SIG_7);
        assert!(verify(
            &hex32(GOLDEN_CHILD_PUB_7),
            GOLDEN_SIG_7_MESSAGE,
            &sig
        ));
    }

    fn random_seed() -> [u8; 32] {
        use rand::RngCore as _;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        seed
    }

    #[test]
    fn public_and_private_derivations_agree() {
        let seed = random_seed();
        let master_pub = master_public_from_seed(&seed);
        for namespace in [b"a".as_slice(), b"".as_slice(), b"another-ns"] {
            for index in [0u32, 1, 42, u32::MAX] {
                let signer = ObserverSigner::derive(&seed, namespace, index);
                let public = derive_child_public(&master_pub, namespace, index).unwrap();
                assert_eq!(signer.public_key(), public);
            }
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let seed = random_seed();
        let signer = ObserverSigner::derive(&seed, b"ns", 3);
        let sig = signer.sign(b"a message");
        assert!(verify(&signer.public_key(), b"a message", &sig));
    }

    #[test]
    fn wrong_index_master_namespace_or_message_fails() {
        let seed = random_seed();
        let other_seed = random_seed();
        let master_pub = master_public_from_seed(&seed);
        let signer = ObserverSigner::derive(&seed, b"ns", 5);
        let sig = signer.sign(b"msg");

        let wrong_index = derive_child_public(&master_pub, b"ns", 6).unwrap();
        assert!(!verify(&wrong_index, b"msg", &sig));

        let wrong_master =
            derive_child_public(&master_public_from_seed(&other_seed), b"ns", 5).unwrap();
        assert!(!verify(&wrong_master, b"msg", &sig));

        let wrong_namespace = derive_child_public(&master_pub, b"other", 5).unwrap();
        assert!(!verify(&wrong_namespace, b"msg", &sig));

        let right = derive_child_public(&master_pub, b"ns", 5).unwrap();
        assert!(!verify(&right, b"tampered", &sig));
        assert!(verify(&right, b"msg", &sig));
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = random_seed();
        let a = ObserverSigner::derive(&seed, b"ns", 9);
        let b = ObserverSigner::derive(&seed, b"ns", 9);
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.sign(b"m"), b.sign(b"m"));
    }

    #[test]
    fn verify_rejects_garbage_inputs() {
        assert!(!verify(&[0xffu8; 32], b"msg", &[0u8; 64]));
        let seed = random_seed();
        let signer = ObserverSigner::derive(&seed, b"ns", 0);
        assert!(!verify(&signer.public_key(), b"msg", &[0u8; 64]));
    }

    #[test]
    fn invalid_master_public_errors() {
        // y = 2 has no square root for x on the curve, so decompression fails.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert_eq!(
            derive_child_public(&not_a_point, b"ns", 0),
            Err(DeriveError::InvalidMasterKey)
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let signer = ObserverSigner::derive(&GOLDEN_SEED, b"ns", 0);
        let debug = format!("{signer:?}");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains(&hex::encode(signer.public_key())));
    }
}
