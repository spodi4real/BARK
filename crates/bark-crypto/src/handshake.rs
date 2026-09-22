//! The end-to-end session handshake.
//!
//! Runs *inside* whatever transport carried the two peers together — a direct
//! QUIC connection or a relayed one. The relay carries these messages but
//! cannot learn the session keys, because the keys come from a Diffie-Hellman
//! exchange between the two endpoints and the relay has neither private half.
//!
//! The construction is **SIGMA**: signed ephemeral Diffie-Hellman.
//!
//! ```text
//!   Controller                                   Remote
//!       |  Hello:  nonce_c, ephemeral_c, id_c      |
//!       | ---------------------------------------> |
//!       |                                          |  looks id_c up in its
//!       |                                          |  trust store; refuses
//!       |                                          |  here if not paired
//!       |  Accept: nonce_r, ephemeral_r, id_r,     |
//!       |          signature over the transcript   |
//!       | <--------------------------------------- |
//!       |  Confirm: signature over the transcript  |
//!       | ---------------------------------------> |
//! ```
//!
//! Properties this gives, each of which is a stated requirement:
//!
//! * **Forward secrecy.** The Diffie-Hellman keys are fresh per session and
//!   discarded afterwards. Recording today's traffic and stealing a device's
//!   private key tomorrow does not decrypt it.
//! * **Mutual authentication.** Each side signs a transcript that covers both
//!   ephemeral keys and both identities, so neither can be impersonated and the
//!   signature cannot be lifted into another session.
//! * **Replay resistance.** Fresh random nonces on both sides mean a recorded
//!   handshake cannot be replayed to produce the same keys.
//! * **No trust in the relay.** The server never sees a private key and cannot
//!   substitute its own: doing so would require forging a signature.
//! * **Bound to the connection it runs on.** Both sides mix a *channel
//!   binding* into the signed transcript: a value exported from the QUIC/TLS
//!   connection carrying the handshake. Two endpoints of one genuine QUIC
//!   connection export the same value; anything that terminated TLS in the
//!   middle and ran two separate connections would export two different
//!   values, and both signatures would fail. This is what lets session data
//!   travel under QUIC's own encryption, with no second layer: once this
//!   handshake succeeds, the QUIC connection itself is proven to run between
//!   the two paired devices and nobody else.

use crate::identity::{context, DeviceIdentity, PublicIdentity};
use crate::session::SessionKeys;
use bark_core::{BarkError, Result, PROTOCOL_VERSION};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

/// First message: controller announces itself and offers an ephemeral key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub protocol: u16,
    pub nonce: [u8; 32],
    pub ephemeral: [u8; 32],
    pub identity: PublicIdentity,
}

/// Second message: the remote answers, proving who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accept {
    pub nonce: [u8; 32],
    pub ephemeral: [u8; 32],
    pub identity: PublicIdentity,
    pub signature: [u8; 64],
}

/// Third message: the controller proves who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub signature: [u8; 64],
}

/// Builds the transcript hash both sides sign.
///
/// Every field of both hello messages is covered, each length-prefixed so that
/// no combination of field values can be reinterpreted as a different
/// combination. If any byte of the exchange differs between the two peers —
/// because something tampered with it in flight — the hashes differ, the
/// signatures fail, and the handshake is abandoned.
fn transcript(
    channel: &[u8; 32],
    hello: &Hello,
    nonce_r: &[u8; 32],
    eph_r: &[u8; 32],
    id_r: &PublicIdentity,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BARK-v1/handshake-transcript");
    // Never sent: each side computes it from its own end of the connection.
    h.update(channel);
    h.update(hello.protocol.to_be_bytes());
    h.update(hello.nonce);
    h.update(hello.ephemeral);
    h.update(hello.identity.as_bytes());
    h.update(nonce_r);
    h.update(eph_r);
    h.update(id_r.as_bytes());
    let out = h.finalize();
    let mut t = [0u8; 32];
    t.copy_from_slice(&out);
    t
}

/// Derives the two directional keys and the session binding from the shared
/// secret, salted with the transcript so two sessions that somehow produced the
/// same Diffie-Hellman output would still get different keys.
fn derive(shared: &[u8; 32], transcript: &[u8; 32]) -> Result<SessionKeys_> {
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut c2r = Zeroizing::new([0u8; 32]);
    let mut r2c = Zeroizing::new([0u8; 32]);
    let mut binding = [0u8; 32];
    hk.expand(b"BARK-v1/key/controller-to-remote", c2r.as_mut_slice())
        .map_err(|_| BarkError::Crypto("key derivation failed".into()))?;
    hk.expand(b"BARK-v1/key/remote-to-controller", r2c.as_mut_slice())
        .map_err(|_| BarkError::Crypto("key derivation failed".into()))?;
    hk.expand(b"BARK-v1/session-binding", &mut binding)
        .map_err(|_| BarkError::Crypto("key derivation failed".into()))?;
    Ok(SessionKeys_ { c2r, r2c, binding })
}

struct SessionKeys_ {
    c2r: Zeroizing<[u8; 32]>,
    r2c: Zeroizing<[u8; 32]>,
    binding: [u8; 32],
}

fn random_32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b)
        .map_err(|e| BarkError::Crypto(format!("no secure random source available: {e}")))?;
    Ok(b)
}

/// Creates a fresh Diffie-Hellman keypair for one session.
///
/// `StaticSecret` rather than `EphemeralSecret` only because the latter
/// requires an older random-number trait than the rest of BARK uses. The value
/// is still used exactly once and dropped at the end of the handshake, which is
/// what makes the exchange forward-secret; the type name does not change that.
fn new_dh_keypair() -> Result<(StaticSecret, [u8; 32])> {
    let secret = StaticSecret::from(random_32()?);
    let public = XPublicKey::from(&secret);
    Ok((secret, public.to_bytes()))
}

/// Controller side, waiting for the remote's answer.
pub struct Initiator {
    identity_public: PublicIdentity,
    hello: Hello,
    secret: StaticSecret,
    channel: [u8; 32],
}

impl Initiator {
    /// Starts a handshake. Returns the message to send.
    ///
    /// `channel` is the binding exported from the connection this handshake
    /// travels on (see the module documentation). Tests and benchmarks that
    /// have no connection pass any fixed value, the same on both sides.
    pub fn start(identity: &DeviceIdentity, channel: &[u8; 32]) -> Result<(Self, Hello)> {
        let (secret, ephemeral) = new_dh_keypair()?;
        let hello = Hello {
            protocol: PROTOCOL_VERSION,
            nonce: random_32()?,
            ephemeral,
            identity: identity.public(),
        };
        Ok((
            Initiator {
                identity_public: identity.public(),
                hello: hello.clone(),
                secret,
                channel: *channel,
            },
            hello,
        ))
    }

    /// Processes the remote's answer and completes the handshake.
    ///
    /// `expected` is the identity the operator asked to connect to, taken from
    /// the favourites entry. Checking it here is what stops the coordination
    /// server from quietly pointing a connection at a different machine: the
    /// server chooses who to route to, so the controller must verify the answer
    /// came from the device it meant.
    pub fn finish(
        self,
        identity: &DeviceIdentity,
        accept: &Accept,
        expected: Option<&PublicIdentity>,
    ) -> Result<(SessionKeys, Confirm)> {
        if let Some(want) = expected {
            if want.fingerprint() != accept.identity.fingerprint() {
                return Err(BarkError::Crypto(format!(
                    "Connected to the wrong computer.\n\n\
                     Expected: {}\n\
                     Answered: {}\n\n\
                     The connection was refused. This can mean the remote computer was \
                     reinstalled and has a new identity, or that something is interfering \
                     with the connection.",
                    want.device_id(),
                    accept.identity.device_id()
                )));
            }
        }

        let t = transcript(
            &self.channel,
            &self.hello,
            &accept.nonce,
            &accept.ephemeral,
            &accept.identity,
        );

        // Verify before doing any key agreement, so an unauthenticated peer
        // cannot make us do work or influence derived material.
        accept
            .identity
            .verify(context::HANDSHAKE, &t, &accept.signature)
            .map_err(|_| {
                BarkError::Crypto(
                    "The remote computer failed to prove its identity. The connection was refused."
                        .into(),
                )
            })?;

        let their_eph = XPublicKey::from(accept.ephemeral);
        let shared = self.secret.diffie_hellman(&their_eph);
        if !shared.was_contributory() {
            // A zero shared secret means the peer sent a low-order point, which
            // would force the key to a known value.
            return Err(BarkError::Crypto(
                "The remote computer sent an invalid key. The connection was refused.".into(),
            ));
        }

        let k = derive(shared.as_bytes(), &t)?;
        let confirm = Confirm { signature: identity.sign(context::HANDSHAKE, &t) };
        debug_assert_eq!(self.identity_public, identity.public());

        Ok((SessionKeys::new(k.c2r, k.r2c, k.binding, true), confirm))
    }
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never renders the Diffie-Hellman secret.
        write!(f, "Initiator(self={})", self.identity_public.device_id())
    }
}

/// Remote side, waiting for the controller's proof.
pub struct Responder {
    transcript: [u8; 32],
    peer: PublicIdentity,
    keys: SessionKeys_,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never renders the derived session keys.
        write!(f, "Responder(peer={})", self.peer.device_id())
    }
}

impl Responder {
    /// Processes the controller's hello and produces the answer.
    ///
    /// `authorise` is called with the claiming identity *before* any key
    /// agreement happens, and is where the trust store says yes or no. Failing
    /// fast here means an unpaired device costs one signature verification, not
    /// a full session setup.
    pub fn accept<F>(
        identity: &DeviceIdentity,
        hello: &Hello,
        channel: &[u8; 32],
        authorise: F,
    ) -> Result<(Self, Accept)>
    where
        F: FnOnce(&PublicIdentity) -> Result<()>,
    {
        if hello.protocol != PROTOCOL_VERSION {
            return Err(BarkError::Protocol(format!(
                "The other computer is running a different version of BARK \
                 (protocol {} against {}). Update both computers to the same version.",
                hello.protocol, PROTOCOL_VERSION
            )));
        }

        authorise(&hello.identity)?;

        let (secret, ephemeral) = new_dh_keypair()?;
        let nonce = random_32()?;
        let t = transcript(channel, hello, &nonce, &ephemeral, &identity.public());

        let their_eph = XPublicKey::from(hello.ephemeral);
        let shared = secret.diffie_hellman(&their_eph);
        if !shared.was_contributory() {
            return Err(BarkError::Crypto(
                "The connecting computer sent an invalid key. The connection was refused.".into(),
            ));
        }

        let keys = derive(shared.as_bytes(), &t)?;
        let accept = Accept {
            nonce,
            ephemeral,
            identity: identity.public(),
            signature: identity.sign(context::HANDSHAKE, &t),
        };

        Ok((Responder { transcript: t, peer: hello.identity, keys }, accept))
    }

    /// Verifies the controller's proof. Only after this succeeds is the session
    /// authenticated in both directions.
    pub fn finish(self, confirm: &Confirm) -> Result<SessionKeys> {
        self.peer
            .verify(context::HANDSHAKE, &self.transcript, &confirm.signature)
            .map_err(|_| {
                BarkError::Crypto(
                    "The connecting computer failed to prove its identity. \
                     The connection was refused."
                        .into(),
                )
            })?;
        Ok(SessionKeys::new(self.keys.c2r, self.keys.r2c, self.keys.binding, false))
    }

    pub fn peer(&self) -> &PublicIdentity {
        &self.peer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the value both ends of one QUIC connection would export.
    const CH: [u8; 32] = [0x5a; 32];

    fn allow_any(_: &PublicIdentity) -> Result<()> {
        Ok(())
    }

    #[test]
    fn a_handshake_carried_across_two_different_connections_fails() {
        // A relay (or anything else) that terminated TLS itself and ran one
        // connection to each peer: the two sides export different bindings.
        // It may pass every message through untouched and still must fail.
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let controller_side = [1u8; 32];
        let remote_side = [2u8; 32];

        let (init, hello) = Initiator::start(&controller, &controller_side).unwrap();
        let (resp, accept) = Responder::accept(&remote, &hello, &remote_side, allow_any).unwrap();
        assert!(
            init.finish(&controller, &accept, Some(&remote.public())).is_err(),
            "the controller must refuse an answer signed over another connection"
        );

        // And the other direction: even a confirm computed on the controller's
        // connection must not satisfy the remote.
        let (init, hello) = Initiator::start(&controller, &controller_side).unwrap();
        let (resp2, accept2) = Responder::accept(&remote, &hello, &controller_side, allow_any).unwrap();
        let (_, confirm) = init.finish(&controller, &accept2, None).unwrap();
        drop(resp2);
        assert!(resp.finish(&confirm).is_err(), "a confirm from another connection must fail");
    }

    fn run() -> (SessionKeys, SessionKeys, DeviceIdentity, DeviceIdentity) {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();

        let (init, hello) = Initiator::start(&controller, &CH).unwrap();
        let (resp, accept) = Responder::accept(&remote, &hello, &CH, allow_any).unwrap();
        let (ckeys, confirm) = init.finish(&controller, &accept, Some(&remote.public())).unwrap();
        let rkeys = resp.finish(&confirm).unwrap();
        (ckeys, rkeys, controller, remote)
    }

    #[test]
    fn both_sides_derive_the_same_session() {
        let (ckeys, rkeys, _, _) = run();
        assert_eq!(ckeys.binding(), rkeys.binding());
        assert_eq!(ckeys.verification_words(), rkeys.verification_words());
    }

    #[test]
    fn the_derived_keys_actually_work_in_both_directions() {
        let (ckeys, rkeys, _, _) = run();
        let (mut c_seal, mut c_open) = ckeys.into_cipher();
        let (mut r_seal, mut r_open) = rkeys.into_cipher();

        let (seq, msg) = c_seal.seal(b"h", b"key press A").unwrap();
        assert_eq!(r_open.open(seq, b"h", &msg).unwrap(), b"key press A");

        let (seq, frame) = r_seal.seal(b"h", b"video frame").unwrap();
        assert_eq!(c_open.open(seq, b"h", &frame).unwrap(), b"video frame");
    }

    #[test]
    fn two_handshakes_produce_different_keys() {
        let (a, _, _, _) = run();
        let (b, _, _, _) = run();
        assert_ne!(a.binding(), b.binding(), "sessions must not share keys");
    }

    #[test]
    fn an_unpaired_device_is_refused_before_key_agreement() {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (_, hello) = Initiator::start(&controller, &CH).unwrap();

        let err = Responder::accept(&remote, &hello, &CH, |_| {
            Err(BarkError::NotTrusted("BA-TEST-TEST".into()))
        })
        .unwrap_err();
        assert!(matches!(err, BarkError::NotTrusted(_)), "got {err:?}");
    }

    #[test]
    fn the_authorisation_callback_sees_the_real_claiming_identity() {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (_, hello) = Initiator::start(&controller, &CH).unwrap();

        let mut seen = None;
        let _ = Responder::accept(&remote, &hello, &CH, |id| {
            seen = Some(*id);
            Ok(())
        });
        assert_eq!(seen.map(|s| s.fingerprint()), Some(controller.public().fingerprint()));
    }

    #[test]
    fn connecting_to_an_unexpected_device_is_refused() {
        let controller = DeviceIdentity::generate().unwrap();
        let actual_remote = DeviceIdentity::generate().unwrap();
        let intended_remote = DeviceIdentity::generate().unwrap();

        let (init, hello) = Initiator::start(&controller, &CH).unwrap();
        let (_, accept) = Responder::accept(&actual_remote, &hello, &CH, allow_any).unwrap();

        // The server routed us somewhere else. We must notice.
        let err = init
            .finish(&controller, &accept, Some(&intended_remote.public()))
            .unwrap_err();
        assert!(format!("{err}").contains("wrong computer"), "got {err}");
    }

    #[test]
    fn a_tampered_accept_signature_is_rejected() {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (init, hello) = Initiator::start(&controller, &CH).unwrap();
        let (_, mut accept) = Responder::accept(&remote, &hello, &CH, allow_any).unwrap();

        accept.signature[0] ^= 0xff;
        assert!(init.finish(&controller, &accept, None).is_err());
    }

    #[test]
    fn a_tampered_ephemeral_key_is_rejected() {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (init, hello) = Initiator::start(&controller, &CH).unwrap();
        let (_, mut accept) = Responder::accept(&remote, &hello, &CH, allow_any).unwrap();

        // A relay in the middle swaps in its own key. The signature covers the
        // transcript, which covers the ephemeral, so this must fail.
        accept.ephemeral = new_dh_keypair().unwrap().1;
        assert!(
            init.finish(&controller, &accept, None).is_err(),
            "a substituted ephemeral key must break the handshake"
        );
    }

    #[test]
    fn a_tampered_confirm_signature_is_rejected() {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (init, hello) = Initiator::start(&controller, &CH).unwrap();
        let (resp, accept) = Responder::accept(&remote, &hello, &CH, allow_any).unwrap();
        let (_, mut confirm) = init.finish(&controller, &accept, None).unwrap();

        confirm.signature[10] ^= 0x01;
        assert!(resp.finish(&confirm).is_err());
    }

    #[test]
    fn a_confirm_from_a_different_session_is_rejected() {
        // Replaying a valid signature captured from another handshake must not
        // authenticate this one.
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();

        let (init1, hello1) = Initiator::start(&controller, &CH).unwrap();
        let (_, accept1) = Responder::accept(&remote, &hello1, &CH, allow_any).unwrap();
        let (_, confirm1) = init1.finish(&controller, &accept1, None).unwrap();

        let (_init2, hello2) = Initiator::start(&controller, &CH).unwrap();
        let (resp2, _accept2) = Responder::accept(&remote, &hello2, &CH, allow_any).unwrap();

        assert!(
            resp2.finish(&confirm1).is_err(),
            "a signature from another session must not be reusable"
        );
    }

    #[test]
    fn a_protocol_version_mismatch_is_reported_clearly() {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (_, mut hello) = Initiator::start(&controller, &CH).unwrap();
        hello.protocol = PROTOCOL_VERSION + 1;

        let err = Responder::accept(&remote, &hello, &CH, allow_any).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("different version"), "got {text}");
        assert!(text.contains("Update"), "the message should say what to do: {text}");
    }

    #[test]
    fn a_low_order_ephemeral_key_is_refused() {
        // All-zero is a low-order point; accepting it would force a predictable
        // shared secret.
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (_, mut hello) = Initiator::start(&controller, &CH).unwrap();
        hello.ephemeral = [0u8; 32];

        let err = Responder::accept(&remote, &hello, &CH, allow_any).unwrap_err();
        assert!(format!("{err}").contains("invalid key"), "got {err}");
    }

    #[test]
    fn the_responder_reports_who_connected() {
        let controller = DeviceIdentity::generate().unwrap();
        let remote = DeviceIdentity::generate().unwrap();
        let (_, hello) = Initiator::start(&controller, &CH).unwrap();
        let (resp, _) = Responder::accept(&remote, &hello, &CH, allow_any).unwrap();
        assert_eq!(resp.peer().fingerprint(), controller.public().fingerprint());
    }
}
