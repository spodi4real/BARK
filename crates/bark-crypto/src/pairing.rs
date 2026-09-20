//! Pairing codes.
//!
//! A pairing code exists for one purpose: to prove, once, that the person
//! asking for access is standing in front of the target machine or has been
//! told the code by someone who is. After that first success the requesting
//! device's public key is in the trust store and the code is never used again.
//!
//! Design constraints that shaped this:
//!
//! * **Readable over the phone.** Six characters from an alphabet with no
//!   confusable pairs.
//! * **Not guessable in the time it is alive.** 32^6 is about 10^9. With the
//!   attempt limiting in [`AttemptLimiter`], an attacker gets a handful of tries
//!   before being locked out for hours, so the realistic success probability is
//!   negligible.
//! * **Compared in constant time.** A naive `==` on strings leaks how many
//!   leading characters were right, which turns 10^9 guesses into about 200.
//! * **Never logged.** The code is a credential for the length of its life.

use bark_core::{BarkError, Result};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Same alphabet as the Device ID: no I, L, O or U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of characters in a pairing code.
pub const CODE_LEN: usize = 6;

/// How long a freshly generated code stays valid, in microseconds.
///
/// Ten minutes is long enough to walk to another room and read it out, short
/// enough that a code left on screen overnight is not a standing invitation.
/// This expiry applies **only** to the code, never to the trust it establishes.
pub const CODE_LIFETIME_US: u64 = 10 * 60 * 1_000_000;

/// A one-time pairing code, held only in memory on the machine that issued it.
pub struct PairingCode {
    text: Zeroizing<String>,
    issued_us: u64,
    expires_us: u64,
}

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The code is a credential; a stray {:?} must not put it in a log.
        write!(f, "PairingCode(<redacted>, expires_in={}s)", self.seconds_remaining())
    }
}

impl PairingCode {
    /// Generates a fresh code from the system random source.
    pub fn generate() -> Result<Self> {
        let now = bark_core::clock::now_us();
        let mut raw = Zeroizing::new([0u8; CODE_LEN]);
        getrandom::fill(raw.as_mut_slice())
            .map_err(|e| BarkError::Crypto(format!("no secure random source available: {e}")))?;

        // Rejection-free mapping is not possible for 256 % 32 != 0, but 256 is
        // an exact multiple of 32, so taking the low five bits is uniform.
        let mut text = String::with_capacity(CODE_LEN);
        for &b in raw.iter() {
            text.push(ALPHABET[(b & 0x1f) as usize] as char);
        }

        Ok(PairingCode {
            text: Zeroizing::new(text),
            issued_us: now,
            expires_us: now + CODE_LIFETIME_US,
        })
    }

    /// The code as the operator should read it: `XXX-XXX`.
    pub fn display(&self) -> String {
        format!("{}-{}", &self.text[..3], &self.text[3..])
    }

    /// The raw six characters, for comparison. Kept private-ish deliberately:
    /// callers should prefer [`verify`].
    fn raw(&self) -> &str {
        &self.text
    }

    pub fn issued_us(&self) -> u64 {
        self.issued_us
    }

    pub fn is_expired(&self) -> bool {
        bark_core::clock::now_us() >= self.expires_us
    }

    pub fn seconds_remaining(&self) -> u64 {
        self.expires_us.saturating_sub(bark_core::clock::now_us()) / 1_000_000
    }

    /// Checks a code supplied by a remote device.
    ///
    /// Normalises the input the same way a Device ID is normalised, so the
    /// operator can type it with or without the hyphen, in any case, and with
    /// the usual letter/digit confusions.
    pub fn verify(&self, supplied: &str) -> bool {
        if self.is_expired() {
            return false;
        }
        let normalised = match normalise(supplied) {
            Some(n) => n,
            None => return false,
        };
        // Constant-time: never return early on the first differing character.
        normalised.as_bytes().ct_eq(self.raw().as_bytes()).into()
    }
}

/// Cleans up whatever the operator typed into canonical form, or returns `None`
/// if it cannot be a pairing code at all.
fn normalise(input: &str) -> Option<Zeroizing<String>> {
    let mut out = String::with_capacity(CODE_LEN);
    for c in input.chars() {
        let c = c.to_ascii_uppercase();
        let c = match c {
            '-' | ' ' | '_' | '.' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        if out.len() == CODE_LEN {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_LEN).then(|| Zeroizing::new(out))
}

/// Commitment to a pairing code, safe to send through the coordination server.
///
/// The server relays pairing requests but must never learn the code, because a
/// server that knows the code could pair itself with any device. The requester
/// sends `SHA-256(context || code || nonce)`; the target, which knows the code,
/// recomputes it. The nonce stops a passive observer from building a rainbow
/// table over the small code space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeCommitment {
    pub nonce: [u8; 16],
    pub digest: [u8; 32],
}

impl CodeCommitment {
    pub fn create(code: &str) -> Result<Self> {
        let normalised = normalise(code)
            .ok_or_else(|| BarkError::Crypto("that is not a valid pairing code".into()))?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|e| BarkError::Crypto(format!("no secure random source available: {e}")))?;
        Ok(CodeCommitment { digest: digest(&normalised, &nonce), nonce })
    }

    /// Checked by the device that issued the code.
    pub fn matches(&self, issued: &PairingCode) -> bool {
        if issued.is_expired() {
            return false;
        }
        let expected = digest(issued.raw(), &self.nonce);
        let eq: bool = expected.ct_eq(&self.digest).into();
        eq
    }
}

fn digest(code: &str, nonce: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BARK-v1/pairing-code");
    h.update(nonce);
    h.update(code.as_bytes());
    let out = h.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out);
    d
}

/// Rate limits failed pairing attempts.
///
/// Held per requesting device on the machine being paired to. The backoff is
/// exponential and the window is long, because a pairing code is typed by a
/// human at most a few times: a legitimate operator is never inconvenienced by
/// a limit that starts biting at the fourth wrong code, while an attacker is
/// reduced to a handful of guesses per day against a 10^9 space.
#[derive(Debug, Clone)]
pub struct AttemptLimiter {
    failures: u32,
    locked_until_us: u64,
    last_failure_us: u64,
}

/// Failures allowed before any delay is imposed.
const FREE_ATTEMPTS: u32 = 3;
/// Delay after the first penalised failure.
const BASE_LOCKOUT_US: u64 = 5 * 1_000_000;
/// Ceiling on the delay, so a device is never permanently bricked by an
/// attacker deliberately failing pairing against it.
const MAX_LOCKOUT_US: u64 = 60 * 60 * 1_000_000;
/// Counters reset after this long without a failure.
const DECAY_US: u64 = 6 * 60 * 60 * 1_000_000;

impl Default for AttemptLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl AttemptLimiter {
    pub fn new() -> Self {
        AttemptLimiter { failures: 0, locked_until_us: 0, last_failure_us: 0 }
    }

    /// Whether an attempt may be made right now.
    pub fn check(&mut self) -> Result<()> {
        self.check_at(bark_core::clock::now_us())
    }

    pub fn check_at(&mut self, now: u64) -> Result<()> {
        if self.last_failure_us != 0 && now.saturating_sub(self.last_failure_us) > DECAY_US {
            self.failures = 0;
            self.locked_until_us = 0;
        }
        if now < self.locked_until_us {
            let secs = (self.locked_until_us - now).div_ceil(1_000_000);
            return Err(BarkError::Crypto(format!(
                "Too many incorrect pairing codes. Try again in {} seconds.",
                secs
            )));
        }
        Ok(())
    }

    pub fn record_failure(&mut self) {
        self.record_failure_at(bark_core::clock::now_us())
    }

    pub fn record_failure_at(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure_us = now;
        if self.failures > FREE_ATTEMPTS {
            let steps = (self.failures - FREE_ATTEMPTS - 1).min(20);
            let delay = BASE_LOCKOUT_US.saturating_mul(1u64 << steps).min(MAX_LOCKOUT_US);
            self.locked_until_us = now + delay;
        }
    }

    /// Called after a successful pairing; clears the record entirely.
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.locked_until_us = 0;
        self.last_failure_us = 0;
    }

    pub fn failure_count(&self) -> u32 {
        self.failures
    }

    pub fn is_locked(&self) -> bool {
        bark_core::clock::now_us() < self.locked_until_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_have_the_right_shape() {
        let c = PairingCode::generate().unwrap();
        let shown = c.display();
        assert_eq!(shown.len(), CODE_LEN + 1, "got {shown}");
        assert_eq!(shown.as_bytes()[3], b'-');
        for ch in shown.bytes().filter(|&b| b != b'-') {
            assert!(ALPHABET.contains(&ch), "{} is not in the alphabet", ch as char);
        }
    }

    #[test]
    fn generated_codes_differ() {
        let a = PairingCode::generate().unwrap();
        let b = PairingCode::generate().unwrap();
        assert_ne!(a.display(), b.display());
    }

    #[test]
    fn verifies_however_the_operator_types_it() {
        let c = PairingCode::generate().unwrap();
        let shown = c.display();
        let raw = shown.replace('-', "");
        assert!(c.verify(&shown));
        assert!(c.verify(&raw));
        assert!(c.verify(&raw.to_lowercase()));
        assert!(c.verify(&format!(" {} ", shown.to_lowercase())));
        assert!(c.verify(&format!("{} {}", &raw[..3], &raw[3..])));
    }

    #[test]
    fn rejects_wrong_codes_and_junk() {
        let c = PairingCode::generate().unwrap();
        assert!(!c.verify(""));
        assert!(!c.verify("ABC"));
        assert!(!c.verify("ABCDEFG"));
        assert!(!c.verify("!!!!!!"));
        // A code differing in one character only.
        let mut wrong: Vec<char> = c.raw().chars().collect();
        wrong[5] = if wrong[5] == '0' { '1' } else { '0' };
        assert!(!c.verify(&wrong.into_iter().collect::<String>()));
    }

    #[test]
    fn expired_codes_never_verify() {
        let mut c = PairingCode::generate().unwrap();
        let shown = c.display();
        assert!(c.verify(&shown));
        c.expires_us = 0; // force expiry
        assert!(c.is_expired());
        assert!(!c.verify(&shown), "an expired code must not verify");
    }

    #[test]
    fn debug_output_does_not_reveal_the_code() {
        let c = PairingCode::generate().unwrap();
        let d = format!("{c:?}");
        assert!(!d.contains(c.raw()), "the code leaked into debug output");
        assert!(d.contains("redacted"));
    }

    #[test]
    fn commitment_matches_only_the_issuing_code() {
        let issued = PairingCode::generate().unwrap();
        let other = PairingCode::generate().unwrap();

        let commit = CodeCommitment::create(&issued.display()).unwrap();
        assert!(commit.matches(&issued));
        assert!(!commit.matches(&other));
    }

    #[test]
    fn commitment_hides_the_code_and_is_salted() {
        let issued = PairingCode::generate().unwrap();
        let a = CodeCommitment::create(&issued.display()).unwrap();
        let b = CodeCommitment::create(&issued.display()).unwrap();
        // Same code, different nonce, so the digests must differ; otherwise the
        // server could recognise a repeated code.
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.digest, b.digest);
        // And neither digest contains the code.
        let code_bytes = issued.raw().as_bytes();
        assert!(!a.digest.windows(code_bytes.len()).any(|w| w == code_bytes));
    }

    #[test]
    fn commitment_rejects_a_malformed_code() {
        assert!(CodeCommitment::create("nope").is_err());
        assert!(CodeCommitment::create("").is_err());
    }

    #[test]
    fn limiter_allows_a_few_mistakes_then_backs_off() {
        let mut l = AttemptLimiter::new();
        let t0 = 1_000_000_000u64;

        // The first three failures cost nothing: people mistype.
        for _ in 0..FREE_ATTEMPTS {
            l.check_at(t0).expect("should still be allowed");
            l.record_failure_at(t0);
        }
        l.check_at(t0).expect("still allowed at the limit");

        // The fourth triggers a lockout.
        l.record_failure_at(t0);
        assert!(l.check_at(t0).is_err(), "should be locked out now");

        // And it clears once the delay passes.
        l.check_at(t0 + BASE_LOCKOUT_US).expect("lockout should expire");
    }

    #[test]
    fn lockout_grows_but_is_capped() {
        let mut l = AttemptLimiter::new();
        let mut t = 1_000_000_000u64;
        for _ in 0..40 {
            l.record_failure_at(t);
            t = l.locked_until_us;
        }
        let final_delay = l.locked_until_us - t.min(l.locked_until_us);
        assert!(final_delay <= MAX_LOCKOUT_US);
        // Never permanently locked: the cap must be reachable and finite.
        l.check_at(l.locked_until_us + 1).expect("must eventually unlock");
    }

    #[test]
    fn success_and_time_both_clear_the_record() {
        let mut l = AttemptLimiter::new();
        let t0 = 1_000_000_000u64;
        for _ in 0..6 {
            l.record_failure_at(t0);
        }
        assert!(l.check_at(t0).is_err());

        l.record_success();
        assert_eq!(l.failure_count(), 0);
        l.check_at(t0).expect("success should clear the lockout");

        // Separately, a long quiet period decays the counter.
        let mut l2 = AttemptLimiter::new();
        for _ in 0..6 {
            l2.record_failure_at(t0);
        }
        l2.check_at(t0 + DECAY_US + 1).expect("counters should decay");
        assert_eq!(l2.failure_count(), 0);
    }

    #[test]
    fn normalise_maps_confusable_characters() {
        // I -> 1, O -> 0, l -> 1, O -> 0, hyphen dropped, 0, 1
        assert_eq!(normalise("IOlO-01").map(|s| s.to_string()), Some("101001".to_string()));
        assert_eq!(normalise("ABC-DEF").map(|s| s.to_string()), Some("ABCDEF".to_string()));
        assert_eq!(normalise("ABCDEFG"), None, "too long");
        assert_eq!(normalise("ABCDE"), None, "too short");
        assert_eq!(normalise("IOl0-1"), None, "only five code characters");
        assert_eq!(normalise("ABCDEU"), None, "U is not in the alphabet");
    }
}
