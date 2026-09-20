//! The permanent cryptographic identity of one BARK device.
//!
//! Generated once, at install time, and never regenerated. Everything else —
//! the Device ID the operator reads, the trust relationships, the right to open
//! a session — derives from this keypair. Losing it means re-pairing; leaking it
//! means an attacker can impersonate the machine, which is why it lives under
//! DPAPI machine protection in a directory only SYSTEM and Administrators can
//! read.

use bark_core::{paths, BarkError, DeviceId, Fingerprint, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Domain separator prefixed to every signed payload.
///
/// Without it, a signature produced for one purpose (say, a pairing
/// confirmation) could be replayed as a signature for another (a session
/// authentication). Each context gets its own string, so a signature is only
/// ever valid for the exact thing it was made for.
pub mod context {
    pub const SERVER_AUTH: &[u8] = b"BARK-v1/server-auth";
    pub const PEER_AUTH: &[u8] = b"BARK-v1/peer-auth";
    pub const PAIRING: &[u8] = b"BARK-v1/pairing";
    pub const HANDSHAKE: &[u8] = b"BARK-v1/handshake";
    pub const REVOCATION: &[u8] = b"BARK-v1/revocation";
}

/// An Ed25519 signature.
///
/// A newtype rather than a bare `[u8; 64]` because serde only implements its
/// traits for arrays up to 32 elements, and because giving signatures a named
/// type stops them being confused with the many other 32- and 64-byte values
/// this protocol moves around.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

impl Signature64 {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for Signature64 {
    fn from(v: [u8; 64]) -> Self {
        Signature64(v)
    }
}

impl std::fmt::Debug for Signature64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A signature is not secret, but printing 128 hex characters into a log
        // line helps nobody.
        write!(f, "Signature64({}…)", hex::encode(&self.0[..4]))
    }
}

// `Result` in this module is `bark_core::Result`, so the serde impls below
// spell out `std::result::Result` to get serde's own error types.
impl Serialize for Signature64 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        // Raw bytes for the binary wire format; hex when a human will read it.
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Signature64 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Signature64;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a 64-byte Ed25519 signature")
            }

            fn visit_bytes<E: serde::de::Error>(
                self,
                v: &[u8],
            ) -> std::result::Result<Signature64, E> {
                let a: [u8; 64] = v.try_into().map_err(|_| {
                    E::custom(format!("signature must be 64 bytes, got {}", v.len()))
                })?;
                Ok(Signature64(a))
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Signature64, E> {
                let raw = hex::decode(v).map_err(E::custom)?;
                self.visit_bytes(&raw)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Signature64, A::Error> {
                let mut a = [0u8; 64];
                for (i, slot) in a.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Signature64(a))
            }
        }
        d.deserialize_bytes(V)
    }
}

/// A peer's public identity. Comparable, storable, and safe to publish.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicIdentity {
    #[serde(with = "key_bytes")]
    key: [u8; 32],
}

mod key_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("public key must be 32 bytes"))
    }
}

/// Whether the y-coordinate in a compressed Ed25519 encoding is below the
/// field prime.
///
/// Curve25519 decompression reduces the y-coordinate modulo p, so a
/// y-coordinate at or above p decodes to the *same curve point* as some smaller
/// one. That would give one device two different valid-looking public keys —
/// and therefore two different fingerprints and two different Device IDs — for
/// a single private key. Nothing catastrophic follows from it, but a device
/// having exactly one identity is an assumption the trust store and the audit
/// log both rest on, so non-canonical encodings are refused at the door.
fn is_canonical_y(bytes: &[u8; 32]) -> bool {
    // p = 2^255 - 19, little-endian.
    const P: [u8; 32] = [
        0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x7F,
    ];
    let mut y = *bytes;
    // The top bit carries the sign of x, not part of y.
    y[31] &= 0x7F;
    for i in (0..32).rev() {
        if y[i] < P[i] {
            return true;
        }
        if y[i] > P[i] {
            return false;
        }
    }
    // Exactly p is congruent to zero, so it is not canonical either.
    false
}

impl PublicIdentity {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if !is_canonical_y(&bytes) {
            return Err(BarkError::Crypto(
                "invalid public key: the encoding is not canonical".into(),
            ));
        }
        // Reject anything that is not a valid Ed25519 point now, rather than
        // discovering it at verification time inside a connection handler.
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| BarkError::Crypto(format!("invalid public key: {e}")))?;
        Ok(PublicIdentity { key: bytes })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut h = Sha256::new();
        h.update(b"BARK-v1/fingerprint");
        h.update(self.key);
        let out = h.finalize();
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&out);
        Fingerprint(fp)
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_fingerprint(&self.fingerprint())
    }

    /// Verifies a signature made by this identity for a specific purpose.
    pub fn verify(&self, ctx: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.key)
            .map_err(|e| BarkError::Crypto(format!("invalid public key: {e}")))?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| BarkError::Crypto("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&domain_separated(ctx, message), &sig)
            .map_err(|_| BarkError::Crypto("signature verification failed".into()))
    }
}

impl std::fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicIdentity({})", self.device_id())
    }
}

impl std::fmt::Display for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.device_id())
    }
}

/// Binds a message to its purpose before signing, so a signature for one
/// context can never be replayed in another. Length-prefixing the context
/// prevents an attacker from shifting the boundary between the two fields.
fn domain_separated(ctx: &[u8], message: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ctx.len() + message.len() + 2);
    v.push(ctx.len() as u8);
    v.extend_from_slice(ctx);
    v.extend_from_slice(message);
    v
}

/// This device's identity, including the private half.
pub struct DeviceIdentity {
    signing: SigningKey,
    public: PublicIdentity,
    fingerprint: Fingerprint,
    device_id: DeviceId,
    created_unix_us: u64,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately never renders the private key.
        write!(f, "DeviceIdentity({})", self.device_id)
    }
}

/// On-disk form, JSON, wrapped by DPAPI before it touches the filesystem.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    version: u32,
    created_unix_us: u64,
    /// Ed25519 seed, hex. Only ever present inside a DPAPI blob.
    secret_hex: String,
}

impl DeviceIdentity {
    /// Creates a brand new identity from the operating system's cryptographic
    /// random source.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice())
            .map_err(|e| BarkError::Crypto(format!("no secure random source available: {e}")))?;
        Ok(Self::from_seed(&seed, bark_core::clock::unix_us()))
    }

    fn from_seed(seed: &[u8; 32], created_unix_us: u64) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let public = PublicIdentity { key: signing.verifying_key().to_bytes() };
        let fingerprint = public.fingerprint();
        let device_id = DeviceId::from_fingerprint(&fingerprint);
        DeviceIdentity { signing, public, fingerprint, device_id, created_unix_us }
    }

    pub fn public(&self) -> PublicIdentity {
        self.public
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn created_unix_us(&self) -> u64 {
        self.created_unix_us
    }

    /// Signs a message for one specific purpose.
    pub fn sign(&self, ctx: &[u8], message: &[u8]) -> [u8; 64] {
        self.signing.sign(&domain_separated(ctx, message)).to_bytes()
    }

    /// Loads the identity from disk, creating one on first run.
    ///
    /// This is the only function that creates an identity in normal operation,
    /// and it is called by the service at startup. Returns whether a new
    /// identity was generated, so the caller can write the right audit entry.
    pub fn load_or_create() -> Result<(Self, bool)> {
        let path = paths::identity_file();
        if path.exists() {
            match Self::load_from(&path) {
                Ok(id) => return Ok((id, false)),
                Err(e) => {
                    // Refuse to silently replace an identity that merely failed
                    // to load: regenerating would break every pairing on every
                    // other machine, which is far worse than stopping here.
                    return Err(BarkError::Identity(format!(
                        "The BARK device identity at {} could not be read.\n\n{e}\n\n\
                         BARK has NOT created a new identity, because that would break \
                         pairing with every other computer. Restore the file from a backup, \
                         or run \"BARK.exe --reset-identity\" to start over and re-pair.",
                        path.display()
                    )));
                }
            }
        }
        paths::ensure_machine_dirs()?;
        let id = Self::generate()?;
        id.save_to(&path)?;
        Ok((id, true))
    }

    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        let sealed = std::fs::read(path)?;
        let plain = Zeroizing::new(crate::dpapi::unprotect(&sealed)?);
        let stored: StoredIdentity = serde_json::from_slice(&plain)
            .map_err(|e| BarkError::Identity(format!("identity file is not valid: {e}")))?;
        if stored.version != 1 {
            return Err(BarkError::Identity(format!(
                "identity file version {} is newer than this BARK understands",
                stored.version
            )));
        }
        let seed_vec = Zeroizing::new(
            hex::decode(&stored.secret_hex)
                .map_err(|e| BarkError::Identity(format!("identity key is malformed: {e}")))?,
        );
        let seed: [u8; 32] = seed_vec
            .as_slice()
            .try_into()
            .map_err(|_| BarkError::Identity("identity key is the wrong length".into()))?;
        Ok(Self::from_seed(&seed, stored.created_unix_us))
    }

    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        let stored = StoredIdentity {
            version: 1,
            created_unix_us: self.created_unix_us,
            secret_hex: hex::encode(self.signing.to_bytes()),
        };
        let json = Zeroizing::new(
            serde_json::to_vec(&stored)
                .map_err(|e| BarkError::Identity(format!("could not encode identity: {e}")))?,
        );
        let sealed = crate::dpapi::protect(&json)?;
        paths::write_atomic(path, &sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bark-id-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn generated_identities_are_distinct() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.device_id(), b.device_id());
    }

    #[test]
    fn device_id_is_derived_from_the_public_key() {
        let id = DeviceIdentity::generate().unwrap();
        assert_eq!(id.device_id(), id.public().device_id());
        assert_eq!(id.fingerprint(), id.public().fingerprint());
        // And it is stable across repeated derivation.
        assert_eq!(id.public().device_id(), id.public().device_id());
    }

    #[test]
    fn signature_verifies_only_for_its_own_context() {
        let id = DeviceIdentity::generate().unwrap();
        let msg = b"challenge bytes";
        let sig = id.sign(context::PEER_AUTH, msg);

        id.public().verify(context::PEER_AUTH, msg, &sig).expect("same context must verify");
        assert!(
            id.public().verify(context::SERVER_AUTH, msg, &sig).is_err(),
            "a peer-auth signature must not verify as a server-auth signature"
        );
    }

    #[test]
    fn signature_does_not_verify_for_a_different_message_or_key() {
        let id = DeviceIdentity::generate().unwrap();
        let other = DeviceIdentity::generate().unwrap();
        let sig = id.sign(context::PEER_AUTH, b"challenge A");

        assert!(id.public().verify(context::PEER_AUTH, b"challenge B", &sig).is_err());
        assert!(other.public().verify(context::PEER_AUTH, b"challenge A", &sig).is_err());
    }

    #[test]
    fn malformed_signatures_are_rejected_without_panicking() {
        let id = DeviceIdentity::generate().unwrap();
        assert!(id.public().verify(context::PEER_AUTH, b"m", &[]).is_err());
        assert!(id.public().verify(context::PEER_AUTH, b"m", &[0u8; 63]).is_err());
        assert!(id.public().verify(context::PEER_AUTH, b"m", &[0u8; 64]).is_err());
    }

    #[test]
    fn context_length_prefix_prevents_boundary_shifting() {
        // Without the length prefix, ctx="AB" + msg="C" and ctx="A" + msg="BC"
        // would hash identically and a signature would transfer between them.
        assert_ne!(domain_separated(b"AB", b"C"), domain_separated(b"A", b"BC"));
    }

    #[test]
    fn identity_survives_a_save_and_load() {
        let dir = tempdir("save");
        let path = dir.join("identity.dat");

        let original = DeviceIdentity::generate().unwrap();
        original.save_to(&path).unwrap();

        let loaded = DeviceIdentity::load_from(&path).unwrap();
        assert_eq!(loaded.device_id(), original.device_id());
        assert_eq!(loaded.fingerprint(), original.fingerprint());
        assert_eq!(loaded.created_unix_us(), original.created_unix_us());

        // And the reloaded key still signs verifiably.
        let sig = loaded.sign(context::PEER_AUTH, b"after reload");
        original.public().verify(context::PEER_AUTH, b"after reload", &sig).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saved_identity_file_never_contains_the_raw_key() {
        let dir = tempdir("leak");
        let path = dir.join("identity.dat");
        let id = DeviceIdentity::generate().unwrap();
        id.save_to(&path).unwrap();

        let raw = std::fs::read(&path).unwrap();
        let secret = id.signing.to_bytes();
        assert!(
            !raw.windows(32).any(|w| w == secret),
            "the private key is present in the saved file"
        );
        let hex_secret = hex::encode(secret);
        assert!(
            !String::from_utf8_lossy(&raw).contains(&hex_secret),
            "the private key is present in hex in the saved file"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn debug_output_never_reveals_the_private_key() {
        let id = DeviceIdentity::generate().unwrap();
        let d = format!("{id:?}");
        assert!(!d.contains(&hex::encode(id.signing.to_bytes())));
        assert!(d.contains(&id.device_id().to_string()));
    }

    #[test]
    fn public_identity_round_trips_through_json() {
        let id = DeviceIdentity::generate().unwrap();
        let j = serde_json::to_string(&id.public()).unwrap();
        let back: PublicIdentity = serde_json::from_str(&j).unwrap();
        assert_eq!(back, id.public());
    }

    #[test]
    fn invalid_public_keys_are_rejected_at_construction() {
        // All-ones has a y-coordinate above the field prime, so it is a
        // non-canonical encoding of a point that also has a canonical one.
        assert!(PublicIdentity::from_bytes([0xff; 32]).is_err());

        // A real key must still be accepted, and unchanged.
        let real = DeviceIdentity::generate().unwrap().public();
        let back = PublicIdentity::from_bytes(*real.as_bytes()).expect("valid key");
        assert_eq!(back, real);
    }

    #[test]
    fn the_canonical_encoding_check_agrees_with_the_field_prime() {
        // Zero and one are below p.
        assert!(is_canonical_y(&[0u8; 32]));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(is_canonical_y(&one));

        // p itself is not canonical, nor is anything above it.
        let mut p = [0xFFu8; 32];
        p[0] = 0xED;
        p[31] = 0x7F;
        assert!(!is_canonical_y(&p), "p must be rejected");

        let mut p_minus_one = p;
        p_minus_one[0] = 0xEC;
        assert!(is_canonical_y(&p_minus_one), "p-1 must be accepted");

        // The top bit is the sign of x and must be ignored, so setting it on an
        // otherwise canonical value must not change the verdict.
        let mut signed = p_minus_one;
        signed[31] |= 0x80;
        assert!(is_canonical_y(&signed), "the sign bit must not affect the check");

        // Every key BARK generates is canonical.
        for _ in 0..32 {
            let id = DeviceIdentity::generate().unwrap();
            assert!(is_canonical_y(id.public().as_bytes()));
        }
    }
}
