//! Windows Data Protection API wrapper.
//!
//! BARK's device private key has to be readable by a service running as
//! LocalSystem before any user logs in, and must not be readable by copying the
//! file to another machine. DPAPI in **machine scope** is exactly that: Windows
//! holds the master key, derives it from machine state, and refuses to decrypt
//! on a different installation.
//!
//! Machine scope has a known property worth stating plainly: any process running
//! as an administrator on *this* machine can ask DPAPI to decrypt the blob. That
//! is why the file also sits in a directory ACL'd to SYSTEM and Administrators
//! (see `bark_core::paths::harden_directory`). The threat this defends against
//! is a stolen disk or a copied file, not a compromised administrator — nothing
//! defends against a compromised administrator, and claiming otherwise would be
//! dishonest.

use bark_core::{BarkError, Result};

/// Additional entropy mixed into every BARK protection operation.
///
/// This is **not** a key and not a secret — it is a domain separator, so a blob
/// produced by BARK cannot be decrypted by unrelated software on the same
/// machine that also calls DPAPI, and vice versa. The actual protection comes
/// from the machine master key that Windows holds and never exposes.
const ENTROPY: &[u8] = b"BARK.DeviceIdentity.v1";

#[cfg(windows)]
mod imp {
    use super::*;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };
    use windows::Win32::Foundation::{LocalFree, HLOCAL};

    /// Frees a blob Windows allocated with `LocalAlloc`, on every exit path.
    struct BlobGuard(CRYPT_INTEGER_BLOB);

    impl Drop for BlobGuard {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                unsafe {
                    // The plaintext is about to be released back to the heap.
                    // Wipe it first so it does not linger in freed memory.
                    std::ptr::write_bytes(self.0.pbData, 0, self.0.cbData as usize);
                    let _ = LocalFree(Some(HLOCAL(self.0.pbData as *mut _)));
                }
            }
        }
    }

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        let input = blob(plaintext);
        let entropy = blob(ENTROPY);

        unsafe {
            CryptProtectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut out,
            )
            .map_err(|e| {
                BarkError::Crypto(format!(
                    "Windows could not protect the device identity: {e}. \
                     This usually means the Cryptographic Services service is stopped."
                ))
            })?;
        }

        let guard = BlobGuard(out);
        let slice = unsafe { std::slice::from_raw_parts(guard.0.pbData, guard.0.cbData as usize) };
        Ok(slice.to_vec())
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        let input = blob(ciphertext);
        let entropy = blob(ENTROPY);

        unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut out,
            )
            .map_err(|e| {
                BarkError::Crypto(format!(
                    "Windows could not read the device identity: {e}. \
                     The identity file may have been copied from another computer, \
                     or this computer was reinstalled. Re-pair this device to fix it."
                ))
            })?;
        }

        let guard = BlobGuard(out);
        let slice = unsafe { std::slice::from_raw_parts(guard.0.pbData, guard.0.cbData as usize) };
        Ok(slice.to_vec())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    // Present only so the crate builds for non-Windows unit testing. It offers
    // no protection and is never reachable in a shipped build, which targets
    // Windows exclusively.
    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut v = b"UNPROTECTED".to_vec();
        v.extend_from_slice(plaintext);
        Ok(v)
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
        ciphertext
            .strip_prefix(b"UNPROTECTED".as_slice())
            .map(|s| s.to_vec())
            .ok_or_else(|| BarkError::Crypto("not a BARK protected blob".into()))
    }
}

/// Encrypts data so that only this machine can decrypt it.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    imp::protect(plaintext)
}

/// Reverses [`protect`]. Fails if the blob came from a different machine, was
/// tampered with, or was produced by software other than BARK.
pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    imp::unprotect(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_data_round_trips() {
        let secret = b"a 32 byte private key would go here!";
        let sealed = protect(secret).expect("protect");
        let opened = unprotect(&sealed).expect("unprotect");
        assert_eq!(&opened[..], &secret[..]);
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let secret = b"SUPER-SECRET-KEY-MATERIAL-0123456789";
        let sealed = protect(secret).expect("protect");
        assert!(
            !sealed.windows(secret.len()).any(|w| w == secret),
            "the protected blob leaks its plaintext"
        );
    }

    #[cfg(windows)]
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut sealed = protect(b"device key").expect("protect");
        let n = sealed.len();
        sealed[n / 2] ^= 0xff;
        assert!(unprotect(&sealed).is_err(), "tampering was not detected");
    }

    #[cfg(windows)]
    #[test]
    fn empty_input_round_trips() {
        let sealed = protect(b"").expect("protect");
        assert_eq!(unprotect(&sealed).expect("unprotect"), Vec::<u8>::new());
    }
}
