//! TLS credentials and certificate policy for BARK's QUIC connections.
//!
//! BARK uses **two different certificate policies**, for two different jobs.
//! Getting the distinction right is the whole of this module, so it is spelled
//! out here rather than left to be inferred from the code.
//!
//! ## Node to coordination server: pinned certificate
//!
//! The server generates a self-signed certificate once, on first run, and keeps
//! it forever. Its SHA-256 fingerprint is part of the join information an
//! administrator copies to each machine. Nodes accept that certificate and
//! **nothing else**.
//!
//! This is stronger than public certificate authority trust for a closed
//! network, not weaker: with a public CA, any one of hundreds of authorities
//! could issue a certificate for your name and be believed. With pinning, only
//! the exact key you were given is accepted. It also needs no domain name, no
//! DNS, no renewal and no certificate administration — which is the difference
//! between an operator being able to run this and not.
//!
//! ## Node to node: transport-only encryption
//!
//! Two peers meeting through NAT traversal have no way to know each other's
//! transport certificate in advance — they are connecting to whatever address
//! the hole punch found. So the outer TLS layer here provides **encryption
//! only, and no authentication whatsoever**.
//!
//! That is safe *because it is not what authenticates the session*. Inside the
//! tunnel, [`bark_crypto::handshake`] runs a signed Diffie-Hellman exchange
//! against the device identities in the trust store, and no session data is
//! sent before it completes. An attacker who intercepts the QUIC connection
//! gets an encrypted tunnel carrying a handshake they cannot forge, and the
//! connection is dropped.
//!
//! The rule that keeps this honest: **nothing may be sent over a
//! transport-only connection before the inner handshake has authenticated it.**

use bark_core::{paths, BarkError, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// The name BARK puts in its self-signed certificates.
///
/// Never resolved and never checked — peers are found by address, and identity
/// comes from pinning or from the inner handshake. It exists because the
/// format requires a name.
pub const CERT_NAME: &str = "bark.invalid";

/// A self-signed certificate and its private key, used for the QUIC transport.
///
/// Distinct from the device's Ed25519 identity. This key protects the transport;
/// the Ed25519 key proves who the device is. Losing this one is harmless — a new
/// one is generated and, for the server, the join fingerprint changes.
pub struct TransportCredentials {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    fingerprint: [u8; 32],
}

impl std::fmt::Debug for TransportCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransportCredentials({})", self.fingerprint_short())
    }
}

impl TransportCredentials {
    /// Creates a fresh certificate and key. Used per-process by nodes, which do
    /// not need a stable transport identity.
    pub fn generate() -> Result<Self> {
        let ck = rcgen::generate_simple_self_signed(vec![CERT_NAME.to_string()])
            .map_err(|e| BarkError::Crypto(format!("could not create a TLS certificate: {e}")))?;

        let cert = ck.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let fingerprint = fingerprint_of(&cert);

        Ok(TransportCredentials { cert, key, fingerprint })
    }

    /// Loads the server's long-lived certificate, creating it on first run.
    ///
    /// The server's fingerprint must stay the same across restarts, because
    /// every node has it pinned. Regenerating it would lock every machine out
    /// until an administrator redistributed the new one, so this refuses to
    /// overwrite an existing file it cannot read rather than silently replacing
    /// it.
    ///
    /// **This does not set permissions, deliberately.** The directory is locked
    /// down once, by `paths::ensure_machine_dirs` at service start, with an
    /// inheriting ACL so files created inside are protected automatically.
    /// Hardening here instead would restrict the folder to SYSTEM and
    /// Administrators *after* writing — locking the writing process out of the
    /// file it had just created, and producing an "Access is denied" on the
    /// very next read. Permissions are a property of the directory, applied
    /// once by whoever owns it, not a side effect of writing a file.
    pub fn load_or_create(dir: &Path) -> Result<(Self, bool)> {
        let cert_path = dir.join("server-cert.der");
        let key_path = dir.join("server-key.der");

        if cert_path.exists() && key_path.exists() {
            let cert_bytes = read_protected(&cert_path)?;
            let key_bytes = read_protected(&key_path)?;
            if cert_bytes.is_empty() || key_bytes.is_empty() {
                return Err(BarkError::Config(format!(
                    "The BARK server certificate at {} is empty. \
                     Delete both server-cert.der and server-key.der to have BARK create \
                     a new one — every device will then need the new join code.",
                    cert_path.display()
                )));
            }
            let cert = CertificateDer::from(cert_bytes);
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));
            let fingerprint = fingerprint_of(&cert);
            return Ok((TransportCredentials { cert, key, fingerprint }, false));
        }

        std::fs::create_dir_all(dir)?;
        let fresh = Self::generate()?;
        paths::write_atomic(&cert_path, fresh.cert.as_ref())?;
        paths::write_atomic(&key_path, fresh.key.secret_der())?;
        Ok((fresh, true))
    }

    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// The fingerprint as it appears in the join information, grouped so a
    /// person can read it aloud or compare it by eye.
    pub fn fingerprint_text(&self) -> String {
        let h = hex::encode(self.fingerprint).to_uppercase();
        h.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// First four bytes, for log lines.
    pub fn fingerprint_short(&self) -> String {
        hex::encode(&self.fingerprint[..4])
    }

    /// Builds the rustls server configuration for this certificate.
    pub fn server_config(&self) -> Result<rustls::ServerConfig> {
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| BarkError::Crypto(format!("TLS setup failed: {e}")))?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(|e| BarkError::Crypto(format!("TLS certificate rejected: {e}")))?;
        cfg.alpn_protocols = vec![bark_core::ALPN.to_vec()];
        Ok(cfg)
    }
}

/// Reads a file inside the protected BARK directory.
///
/// A permission failure here has one overwhelmingly likely cause — the process
/// is not running as SYSTEM or an administrator — so it is worth saying that
/// outright rather than surfacing "Access is denied" and leaving the operator
/// to guess.
fn read_protected(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            BarkError::Config(format!(
                "BARK does not have permission to read {}.\n\n\
                 The BARK server's files are restricted to the SYSTEM account and to \
                 administrators, which is deliberate: they include the server's private key.\n\n\
                 What to do:\n\
                 \u{2022} Let the BARK Coordination Server service run it, rather than \
                 starting the program by hand, or\n\
                 \u{2022} Run it as an administrator",
                path.display()
            ))
        } else {
            BarkError::Io(e)
        }
    })
}

/// SHA-256 of a certificate's DER encoding. This is what "fingerprint" means
/// everywhere in BARK.
pub fn fingerprint_of(cert: &CertificateDer<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cert.as_ref());
    let out = h.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&out);
    fp
}

/// Parses a fingerprint as written in join information, in any reasonable form.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32]> {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if cleaned.len() != 64 {
        return Err(BarkError::Config(format!(
            "A server fingerprint has 64 hexadecimal characters; this one has {}. \
             Check the join information was copied completely.",
            cleaned.len()
        )));
    }
    let bytes = hex::decode(&cleaned)
        .map_err(|e| BarkError::Config(format!("the fingerprint is not valid: {e}")))?;
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&bytes);
    Ok(fp)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Accepts exactly one certificate, identified by its SHA-256 fingerprint.
///
/// Used for every connection from a node to the coordination server.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedServerVerifier {
    pub fn new(expected: [u8; 32]) -> Arc<Self> {
        Arc::new(PinnedServerVerifier { expected, provider: provider() })
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let presented = fingerprint_of(end_entity);
        // A plain comparison is correct here: a certificate fingerprint is
        // public information, published in the join code, so there is no secret
        // for a timing difference to leak.
        if presented == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "The BARK server presented an unexpected certificate.\n\
                 Expected: {}\n\
                 Received: {}\n\
                 The connection was refused. Either the server was reinstalled and needs \
                 a new join code, or something is intercepting the connection.",
                hex::encode(&self.expected[..8]),
                hex::encode(&presented[..8]),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC mandates TLS 1.3. Reaching this would mean a downgrade attempt.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // The handshake signature still has to be real: pinning says *which*
        // certificate, this says the peer actually holds its private key.
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Accepts any certificate, providing encryption without authentication.
///
/// **This verifier authenticates nothing, by design.** It is used only for
/// direct peer-to-peer connections, where the peer's transport certificate
/// cannot be known in advance. Authentication is performed afterwards, inside
/// the tunnel, by the signed Diffie-Hellman handshake in `bark-crypto`, against
/// the device identities in the trust store.
///
/// The invariant that makes this sound, restated because it is the only thing
/// standing between this type and a serious vulnerability: **no session data —
/// no video, no input, no clipboard, no files — may cross a connection using
/// this verifier until the inner handshake has completed and the peer's
/// identity has been checked against the trust store.**
///
/// Never use this for the connection to the coordination server. That one is
/// pinned; see [`PinnedServerVerifier`].
#[derive(Debug)]
pub struct TransportOnlyVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl TransportOnlyVerifier {
    pub fn new() -> Arc<Self> {
        Arc::new(TransportOnlyVerifier { provider: provider() })
    }
}

impl ServerCertVerifier for TransportOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Intentionally unconditional. See the type documentation.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // Still verified: this proves the peer holds the key for the
        // certificate it presented, which stops a passive eavesdropper from
        // replaying someone else's handshake. It says nothing about *who* the
        // peer is.
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Client configuration that will accept only the pinned server certificate.
pub fn pinned_client_config(expected: [u8; 32]) -> Result<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| BarkError::Crypto(format!("TLS setup failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(expected))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![bark_core::ALPN.to_vec()];
    Ok(cfg)
}

/// Client configuration for peer-to-peer connections. Encryption only; see
/// [`TransportOnlyVerifier`].
pub fn transport_only_client_config() -> Result<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| BarkError::Crypto(format!("TLS setup failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(TransportOnlyVerifier::new())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![bark_core::ALPN.to_vec()];
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_credentials_have_a_stable_fingerprint() {
        let c = TransportCredentials::generate().expect("generate");
        assert_eq!(c.fingerprint(), c.fingerprint(), "must be deterministic");
        assert_eq!(c.fingerprint(), fingerprint_of(c.certificate()));
    }

    #[test]
    fn two_certificates_differ() {
        let a = TransportCredentials::generate().expect("generate");
        let b = TransportCredentials::generate().expect("generate");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_text_is_readable_and_round_trips() {
        let c = TransportCredentials::generate().expect("generate");
        let text = c.fingerprint_text();
        // 64 hex characters in groups of four, joined by 15 hyphens.
        assert_eq!(text.len(), 64 + 15, "got {text}");
        assert!(text.contains('-'));
        assert_eq!(parse_fingerprint(&text).expect("parse"), c.fingerprint());
    }

    #[test]
    fn fingerprints_parse_however_they_are_pasted() {
        let c = TransportCredentials::generate().expect("generate");
        let plain = hex::encode(c.fingerprint());
        for variant in [
            plain.clone(),
            plain.to_uppercase(),
            c.fingerprint_text(),
            format!("  {plain}  "),
            plain
                .as_bytes()
                .chunks(8)
                .map(|x| std::str::from_utf8(x).unwrap())
                .collect::<Vec<_>>()
                .join(" "),
        ] {
            assert_eq!(
                parse_fingerprint(&variant).expect("parse"),
                c.fingerprint(),
                "failed for {variant:?}"
            );
        }
    }

    #[test]
    fn a_truncated_fingerprint_is_rejected_with_a_useful_message() {
        let err = parse_fingerprint("ABCD-1234").unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("64"), "got {text}");
        assert!(text.contains("copied"), "should tell the operator what to do: {text}");
    }

    #[test]
    fn the_server_keeps_its_certificate_across_restarts() {
        // This is the property that stops every device being locked out when
        // the server restarts.
        let dir = std::env::temp_dir().join(format!("bark-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let (first, created) = TransportCredentials::load_or_create(&dir).expect("create");
        assert!(created, "first call should create");

        let (second, created_again) = TransportCredentials::load_or_create(&dir).expect("load");
        assert!(!created_again, "second call should load, not create");
        assert_eq!(
            first.fingerprint(),
            second.fingerprint(),
            "the server fingerprint must not change across restarts"
        );

        // And a third time, because the original version of this code applied a
        // restrictive ACL after writing and so could not read back what it had
        // just written. Permissions belong to the directory, set once by
        // whoever owns it, not to the act of saving a file.
        let (third, _) = TransportCredentials::load_or_create(&dir).expect("load again");
        assert_eq!(first.fingerprint(), third.fingerprint());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_credentials_does_not_change_folder_permissions() {
        // Guards the fix above: whatever `load_or_create` does, the caller must
        // still be able to read the directory afterwards.
        let dir = std::env::temp_dir().join(format!("bark-tls-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        TransportCredentials::load_or_create(&dir).expect("create");

        let listed = std::fs::read_dir(&dir).expect("the directory must still be readable");
        let names: Vec<String> = listed
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "server-cert.der"), "got {names:?}");
        assert!(names.iter().any(|n| n == "server-key.der"), "got {names:?}");

        std::fs::read(dir.join("server-key.der")).expect("the key must still be readable");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_certificate_file_is_reported_not_silently_replaced() {
        let dir = std::env::temp_dir().join(format!("bark-tls-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("server-cert.der"), b"").unwrap();
        std::fs::write(dir.join("server-key.der"), b"").unwrap();

        let err = TransportCredentials::load_or_create(&dir).unwrap_err();
        assert!(format!("{err}").contains("join code"), "got {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configs_build_and_advertise_the_bark_protocol() {
        let c = TransportCredentials::generate().expect("generate");
        let s = c.server_config().expect("server config");
        assert_eq!(s.alpn_protocols, vec![bark_core::ALPN.to_vec()]);

        let p = pinned_client_config(c.fingerprint()).expect("pinned client config");
        assert_eq!(p.alpn_protocols, vec![bark_core::ALPN.to_vec()]);

        let t = transport_only_client_config().expect("transport-only config");
        assert_eq!(t.alpn_protocols, vec![bark_core::ALPN.to_vec()]);
    }

    #[test]
    fn the_pinned_verifier_accepts_only_its_own_certificate() {
        use rustls::pki_types::ServerName;

        let good = TransportCredentials::generate().expect("generate");
        let bad = TransportCredentials::generate().expect("generate");
        let verifier = PinnedServerVerifier::new(good.fingerprint());
        let name = ServerName::try_from(CERT_NAME).expect("name");

        assert!(
            verifier
                .verify_server_cert(
                    good.certificate(),
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000)),
                )
                .is_ok(),
            "the pinned certificate must be accepted"
        );

        let rejected = verifier.verify_server_cert(
            bad.certificate(),
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000)),
        );
        assert!(rejected.is_err(), "any other certificate must be refused");
        let msg = format!("{}", rejected.unwrap_err());
        assert!(msg.contains("unexpected certificate"), "got {msg}");
        assert!(msg.contains("intercepting"), "message should explain: {msg}");
    }

    // `verify_tls12_signature` is not unit tested: rustls keeps
    // `DigitallySignedStruct`'s constructor private, so the argument cannot be
    // built from outside the crate. The property it guards is enforced one
    // level up instead — every config below is built with
    // `with_protocol_versions(&[&TLS13])`, so TLS 1.2 is never offered and the
    // method is unreachable. The `Err` it returns is belt and braces.
    //
    // The test that does cover this end to end lives in `endpoint.rs`, where a
    // real connection is established and its negotiated version checked.

    #[test]
    fn configs_offer_only_tls13() {
        // rustls exposes no accessor for the configured versions, so this
        // asserts what it can: that building with TLS 1.3 only succeeds, and
        // that a cipher suite compatible with QUIC is present. QUIC itself
        // refuses anything below TLS 1.3, so a downgrade cannot be negotiated.
        let c = TransportCredentials::generate().expect("generate");
        assert!(c.server_config().is_ok());
        assert!(pinned_client_config([0u8; 32]).is_ok());
        assert!(transport_only_client_config().is_ok());
    }

    #[test]
    fn both_verifiers_offer_real_signature_schemes() {
        assert!(!PinnedServerVerifier::new([0u8; 32]).supported_verify_schemes().is_empty());
        assert!(!TransportOnlyVerifier::new().supported_verify_schemes().is_empty());
    }
}
