//! Where BARK keeps its files, and who is allowed to read them.
//!
//! Two locations, with a deliberate split:
//!
//! * **`C:\ProgramData\BARK`** — machine state that must exist before anyone
//!   logs in: the device identity, the trust store, the service configuration
//!   and the audit log. Owned by the service. Locked down to SYSTEM and
//!   Administrators so a standard user cannot read the private key or edit the
//!   list of devices allowed to connect.
//! * **`%LOCALAPPDATA%\BARK`** — per-operator preferences: window positions,
//!   favourites ordering, panel visibility. Losing this is harmless.
//!
//! The split matters for the persistence requirement: an upgrade replaces the
//! program files but never touches `ProgramData`, so identity and pairing
//! survive.

use crate::{BarkError, Result};
use std::path::{Path, PathBuf};

/// `C:\ProgramData\BARK` — machine-wide state. Survives upgrades and user
/// profile changes.
pub fn machine_dir() -> PathBuf {
    if let Ok(pd) = std::env::var("ProgramData") {
        if !pd.is_empty() {
            return PathBuf::from(pd).join("BARK");
        }
    }
    #[cfg(windows)]
    if let Some(p) = known_folder_program_data() {
        return p.join("BARK");
    }
    PathBuf::from(r"C:\ProgramData\BARK")
}

/// `%LOCALAPPDATA%\BARK` — preferences for the logged-in operator.
pub fn user_dir() -> PathBuf {
    if let Ok(la) = std::env::var("LOCALAPPDATA") {
        if !la.is_empty() {
            return PathBuf::from(la).join("BARK");
        }
    }
    machine_dir().join("user")
}

/// The encrypted device private key and its public half.
pub fn identity_file() -> PathBuf {
    machine_dir().join("identity.dat")
}

/// Devices this computer trusts, and the devices that trust it.
pub fn trust_store_file() -> PathBuf {
    machine_dir().join("trust.json")
}

/// Node settings: which coordination server to use, capture preferences,
/// security policy.
pub fn node_config_file() -> PathBuf {
    machine_dir().join("config.json")
}

/// Favourites, as maintained by the GUI but stored machine-wide so any
/// administrator on the box sees the same list.
pub fn favourites_file() -> PathBuf {
    machine_dir().join("favourites.json")
}

/// Append-only audit log directory.
pub fn audit_dir() -> PathBuf {
    machine_dir().join("audit")
}

/// Diagnostic logs. Rotated; safe to delete.
pub fn log_dir() -> PathBuf {
    machine_dir().join("logs")
}

/// Coordination server state, including its SQLite database.
pub fn server_dir() -> PathBuf {
    machine_dir().join("server")
}

/// Per-operator GUI preferences.
pub fn user_prefs_file() -> PathBuf {
    user_dir().join("prefs.json")
}

/// Default folder incoming file transfers land in.
pub fn default_downloads_dir() -> PathBuf {
    if let Ok(up) = std::env::var("USERPROFILE") {
        if !up.is_empty() {
            return PathBuf::from(up).join("Downloads").join("BARK");
        }
    }
    machine_dir().join("incoming")
}

/// Creates every directory BARK needs and applies the restrictive ACL to the
/// machine directory. Safe to call repeatedly; called on service start so a
/// deleted folder repairs itself rather than causing a confusing failure later.
pub fn ensure_machine_dirs() -> Result<()> {
    let base = machine_dir();
    std::fs::create_dir_all(&base)?;
    harden_directory(&base)?;
    for sub in [audit_dir(), log_dir(), server_dir()] {
        std::fs::create_dir_all(&sub)?;
    }
    Ok(())
}

pub fn ensure_user_dirs() -> Result<()> {
    std::fs::create_dir_all(user_dir())?;
    Ok(())
}

/// Replaces a directory's permissions with: SYSTEM full control, Administrators
/// full control, inherited by everything inside, and **no inheritance from the
/// parent**. Without the protected flag, `ProgramData`'s default "Users can
/// create" inheritance would remain and a standard user could drop files into
/// BARK's folder.
///
/// A failure here is reported rather than ignored: if the identity file cannot
/// be protected, the operator needs to know.
#[cfg(windows)]
pub fn harden_directory(path: &Path) -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    // D:   discretionary ACL follows
    // P    protected: do not inherit permissions from the parent folder
    // AI   auto-inherited
    // (A;OICI;FA;;;SY)  allow, object+container inherit, full access, SYSTEM
    // (A;OICI;FA;;;BA)  allow, object+container inherit, full access, Administrators
    const SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    let sddl = HSTRING::from(SDDL);
    let mut psd = PSECURITY_DESCRIPTOR::default();

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .map_err(|e| {
            BarkError::Windows(format!("could not build the security descriptor: {e}"))
        })?;

        // Guarantee the descriptor is released on every path out of this block.
        let _guard = LocalFreeGuard(psd.0);

        let mut dacl_present: windows::core::BOOL = Default::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted: windows::core::BOOL = Default::default();
        GetSecurityDescriptorDacl(psd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
            .map_err(|e| BarkError::Windows(format!("could not read the security descriptor: {e}")))?;

        let wide = HSTRING::from(path.as_os_str());
        let rc = SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        );
        if rc.is_err() {
            return Err(BarkError::Windows(format!(
                "could not set permissions on {}: Windows error {}. \
                 Run BARK as an administrator, or repair the installation.",
                path.display(),
                rc.0
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
struct LocalFreeGuard(*mut core::ffi::c_void);

#[cfg(windows)]
impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        if !self.0.is_null() {
            unsafe { let _ = LocalFree(Some(HLOCAL(self.0))); }
        }
    }
}

#[cfg(not(windows))]
pub fn harden_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn known_folder_program_data() -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramData, KF_FLAG_DEFAULT};
    unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None).ok()?;
        let s = p.to_string().ok()?;
        CoTaskMemFree(Some(p.0 as *const _));
        Some(PathBuf::from(s))
    }
}

/// Writes a file so that a crash or power loss mid-write cannot leave a
/// truncated identity or trust store behind. The new contents go to a temporary
/// file in the same directory, are flushed to disk, and only then replace the
/// original with an atomic rename.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        BarkError::Config(format!("{} has no parent directory", path.display()))
    })?;
    std::fs::create_dir_all(parent)?;

    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("bark")
    ));

    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        // Without this the rename can complete while the data is still in the
        // cache, which is exactly how a power cut produces a zero-byte
        // identity file.
        f.sync_all()?;
    }

    // Windows rename fails if the destination exists, so replace explicitly.
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = std::fs::remove_file(path);
            std::fs::rename(&tmp, path).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                BarkError::Io(e)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_dir_is_under_program_data() {
        let d = machine_dir();
        assert!(d.ends_with("BARK"), "{}", d.display());
        assert!(d.is_absolute(), "{}", d.display());
    }

    #[test]
    fn all_machine_paths_live_under_the_machine_directory() {
        let base = machine_dir();
        for p in [
            identity_file(),
            trust_store_file(),
            node_config_file(),
            favourites_file(),
            audit_dir(),
            log_dir(),
            server_dir(),
        ] {
            assert!(p.starts_with(&base), "{} escapes {}", p.display(), base.display());
        }
    }

    #[test]
    fn atomic_write_replaces_existing_contents() {
        let dir = std::env::temp_dir().join(format!("bark-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("thing.json");

        write_atomic(&f, b"first").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"first");

        write_atomic(&f, b"second, which is longer").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"second, which is longer");

        // No temporary files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "temp files were left behind");

        std::fs::remove_dir_all(&dir).ok();
    }
}
