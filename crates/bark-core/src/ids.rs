//! Device identifiers.
//!
//! Two identifiers exist and they serve different jobs:
//!
//! * [`Fingerprint`] is the full SHA-256 of a device's Ed25519 public key. It is
//!   the cryptographic identity. Trust stores key off it, and it is what actually
//!   decides whether a connection is allowed.
//! * [`DeviceId`] is the short human-readable handle, `BA-XXXX-XXXX`, derived
//!   from the first 40 bits of the fingerprint. It exists so a person can read an
//!   ID over the phone. It is a *lookup* handle, never an authentication token.
//!
//! Keeping those separate is deliberate. Forty bits is short enough to grind a
//! colliding key for, so the short ID alone must never grant access. The
//! coordination server additionally refuses to register a second device whose
//! short ID collides with an existing one, so the handle stays unambiguous in
//! practice.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Crockford's Base32 alphabet. `I`, `L`, `O` and `U` are absent: the first
/// three because they are confusable with digits, the last by convention.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Full SHA-256 of a device's Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, the form written to config files and the audit log.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let v = hex::decode(s.trim()).ok()?;
        let arr: [u8; 32] = v.try_into().ok()?;
        Some(Fingerprint(arr))
    }

    /// Grouped hex for display in a Properties dialog, so a human can compare
    /// two fingerprints without losing their place:
    /// `a1b2 c3d4 e5f6 ...`
    pub fn to_display_groups(&self) -> String {
        let h = self.to_hex();
        let mut out = String::with_capacity(h.len() + h.len() / 4);
        for (i, c) in h.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }

    pub fn short_id(&self) -> DeviceId {
        DeviceId::from_fingerprint(self)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the whole thing in a debug log line; the first 8 hex chars
        // are plenty to correlate entries.
        write!(f, "Fingerprint({}…)", &self.to_hex()[..8])
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The short handle: 40 bits, displayed as `BA-XXXX-XXXX`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 5]);

impl DeviceId {
    pub const BYTES: usize = 5;

    pub fn from_fingerprint(fp: &Fingerprint) -> Self {
        let mut b = [0u8; 5];
        b.copy_from_slice(&fp.0[..5]);
        DeviceId(b)
    }

    pub fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }

    /// The eight Base32 characters without the `BA-` prefix or the separator.
    pub fn to_raw_string(&self) -> String {
        let mut out = String::with_capacity(8);
        let v = u64::from(self.0[0]) << 32
            | u64::from(self.0[1]) << 24
            | u64::from(self.0[2]) << 16
            | u64::from(self.0[3]) << 8
            | u64::from(self.0[4]);
        // 40 bits divides evenly into eight 5-bit groups, most significant first.
        for i in (0..8).rev() {
            let idx = ((v >> (i * 5)) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
        out
    }

    /// Parses any reasonable thing an operator might type or paste: with or
    /// without the `BA-` prefix, with or without separators, any case, and with
    /// the Crockford substitutions (`I`/`l` for `1`, `O` for `0`) applied.
    pub fn parse(input: &str) -> Option<Self> {
        let mut bits: u64 = 0;
        let mut count = 0usize;

        // Strip a leading "BA" prefix if present, then read Base32 digits.
        let trimmed = input.trim();
        let upper: Vec<char> = trimmed.chars().map(|c| c.to_ascii_uppercase()).collect();
        let mut start = 0usize;
        if upper.len() >= 2 && upper[0] == 'B' && upper[1] == 'A' {
            start = 2;
        }

        for &c in &upper[start..] {
            let c = match c {
                '-' | ' ' | '_' | '.' | ':' => continue,
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            };
            let idx = ALPHABET.iter().position(|&a| a as char == c)?;
            if count == 8 {
                // More than eight digits: not a device ID.
                return None;
            }
            bits = (bits << 5) | idx as u64;
            count += 1;
        }

        if count != 8 {
            return None;
        }

        Some(DeviceId([
            ((bits >> 32) & 0xff) as u8,
            ((bits >> 24) & 0xff) as u8,
            ((bits >> 16) & 0xff) as u8,
            ((bits >> 8) & 0xff) as u8,
            (bits & 0xff) as u8,
        ]))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.to_raw_string();
        write!(f, "BA-{}-{}", &raw[..4], &raw[4..])
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::str::FromStr for DeviceId {
    type Err = crate::BarkError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DeviceId::parse(s).ok_or_else(|| {
            crate::BarkError::Config(format!(
                "\"{s}\" is not a valid BARK Device ID. \
                 A Device ID looks like BA-4K7P-2WQX."
            ))
        })
    }
}

/// Identifies one remote-control session. Random, not sequential, so session
/// identifiers reveal nothing about how many sessions a device has had.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(first5: [u8; 5]) -> Fingerprint {
        let mut b = [0u8; 32];
        b[..5].copy_from_slice(&first5);
        Fingerprint(b)
    }

    #[test]
    fn roundtrip_all_zero_and_all_one_bits() {
        for bytes in [[0u8; 5], [0xff; 5], [0x01, 0x23, 0x45, 0x67, 0x89]] {
            let id = DeviceId::from_fingerprint(&fp(bytes));
            let text = id.to_string();
            assert_eq!(DeviceId::parse(&text), Some(id), "failed for {text}");
        }
    }

    #[test]
    fn display_shape_is_ba_four_four() {
        let id = DeviceId::from_fingerprint(&fp([0x01, 0x23, 0x45, 0x67, 0x89]));
        let s = id.to_string();
        assert_eq!(s.len(), 12);
        assert!(s.starts_with("BA-"));
        assert_eq!(s.as_bytes()[7], b'-');
    }

    #[test]
    fn parsing_is_forgiving_about_how_a_person_types_it() {
        let id = DeviceId::from_fingerprint(&fp([0xde, 0xad, 0xbe, 0xef, 0x10]));
        let canonical = id.to_string();
        let raw = id.to_raw_string();
        for variant in [
            canonical.clone(),
            canonical.to_lowercase(),
            raw.clone(),
            format!("  {canonical}  "),
            format!("ba {} {}", &raw[..4], &raw[4..]),
            canonical.replace('-', ""),
        ] {
            assert_eq!(DeviceId::parse(&variant), Some(id), "failed for {variant:?}");
        }
    }

    #[test]
    fn crockford_confusable_letters_map_to_digits() {
        // A person reading "BA-1234-5678" aloud may well write I, l or O.
        let with_digits = DeviceId::parse("BA-1234-5670").unwrap();
        assert_eq!(DeviceId::parse("BA-I234-567O"), Some(with_digits));
        assert_eq!(DeviceId::parse("BA-l234-567o"), Some(with_digits));
    }

    #[test]
    fn rejects_wrong_length_and_invalid_characters() {
        assert_eq!(DeviceId::parse(""), None);
        assert_eq!(DeviceId::parse("BA-1234-567"), None, "too short");
        assert_eq!(DeviceId::parse("BA-1234-56789"), None, "too long");
        assert_eq!(DeviceId::parse("BA-1234-567U"), None, "U is not in the alphabet");
        assert_eq!(DeviceId::parse("not an id at all"), None);
    }

    #[test]
    fn fingerprint_hex_roundtrips() {
        let f = fp([1, 2, 3, 4, 5]);
        assert_eq!(Fingerprint::from_hex(&f.to_hex()), Some(f));
    }

    #[test]
    fn debug_for_fingerprint_does_not_print_the_whole_value() {
        let f = fp([0xab, 0xcd, 0xef, 0x01, 0x02]);
        let d = format!("{f:?}");
        assert!(d.len() < 32, "debug output {d} is too long");
        assert!(!d.contains(&f.to_hex()));
    }
}
