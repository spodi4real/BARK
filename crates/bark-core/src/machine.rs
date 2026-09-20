//! Facts about the computer BARK is running on.
//!
//! Used for the device record other machines see (name, OS, version) and for
//! the load figures in the connection information panel.

use serde::{Deserialize, Serialize};

/// The description of this machine published to peers after authentication.
/// Nothing here is sensitive: it is the same information a person reads off the
/// About dialog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineInfo {
    /// NetBIOS/DNS computer name, the default device name.
    pub hostname: String,
    /// For example "Windows 11 Pro 24H2 (build 26200)".
    pub os: String,
    /// BARK version running on this machine.
    pub bark_version: String,
    /// CPU model string.
    pub cpu: String,
    /// Logical processor count.
    pub cpu_threads: u32,
    /// Physical memory in mebibytes.
    pub memory_mb: u32,
}

impl MachineInfo {
    pub fn collect() -> MachineInfo {
        MachineInfo {
            hostname: hostname(),
            os: os_description(),
            bark_version: crate::VERSION.to_string(),
            cpu: cpu_name(),
            cpu_threads: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1),
            memory_mb: physical_memory_mb(),
        }
    }
}

/// The computer's name. This is the default device name in the favourites list
/// and can be overridden by the operator.
pub fn hostname() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::{
            GetComputerNameExW, ComputerNamePhysicalDnsHostname,
        };
        let mut size: u32 = 0;
        unsafe {
            // First call reports the required buffer size and fails with
            // ERROR_MORE_DATA; that is expected.
            let _ = GetComputerNameExW(ComputerNamePhysicalDnsHostname, None, &mut size);
            if size > 0 {
                let mut buf = vec![0u16; size as usize];
                if GetComputerNameExW(
                    ComputerNamePhysicalDnsHostname,
                    Some(windows::core::PWSTR(buf.as_mut_ptr())),
                    &mut size,
                )
                .is_ok()
                {
                    buf.truncate(size as usize);
                    return String::from_utf16_lossy(&buf);
                }
            }
        }
    }
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

/// A readable OS description.
///
/// Read from the registry rather than `GetVersionEx`, which lies about the
/// version unless the executable carries a compatibility manifest declaring
/// support for each Windows release.
pub fn os_description() -> String {
    os_description_impl()
}

#[cfg(windows)]
fn os_description_impl() -> String {
    {
        const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        let product = read_registry_string(KEY, "ProductName").unwrap_or_default();
        let display = read_registry_string(KEY, "DisplayVersion").unwrap_or_default();
        let build = read_registry_string(KEY, "CurrentBuildNumber").unwrap_or_default();

        // Windows 11 still reports "Windows 10 ..." in ProductName; build 22000
        // and above is Windows 11. Correcting it here avoids a confusing entry
        // in the device list.
        let build_num: u32 = build.parse().unwrap_or(0);
        let product = if build_num >= 22000 && product.contains("Windows 10") {
            product.replace("Windows 10", "Windows 11")
        } else {
            product
        };

        let mut s = if product.is_empty() { "Windows".to_string() } else { product };
        if !display.is_empty() {
            s.push(' ');
            s.push_str(&display);
        }
        if build_num > 0 {
            s.push_str(&format!(" (build {build_num})"));
        }
        s
    }
}

#[cfg(not(windows))]
fn os_description_impl() -> String {
    std::env::consts::OS.to_string()
}

pub fn cpu_name() -> String {
    #[cfg(windows)]
    {
        if let Some(s) =
            read_registry_string(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
        {
            return s.trim().to_string();
        }
    }
    "Unknown processor".to_string()
}

pub fn physical_memory_mb() -> u32 {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetPhysicallyInstalledSystemMemory;
        let mut kb: u64 = 0;
        unsafe {
            if GetPhysicallyInstalledSystemMemory(&mut kb).is_ok() {
                return (kb / 1024) as u32;
            }
        }
    }
    0
}

#[cfg(windows)]
fn read_registry_string(subkey: &str, value: &str) -> Option<String> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_VALUE_TYPE,
    };

    let sub = HSTRING::from(subkey);
    let val = HSTRING::from(value);
    let mut key = HKEY::default();

    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(sub.as_ptr()), Some(0), KEY_READ, &mut key)
            .is_err()
        {
            return None;
        }
        // Released on every path below.
        let mut size: u32 = 0;
        let mut kind = REG_VALUE_TYPE(0);
        let rc = RegQueryValueExW(
            key,
            PCWSTR(val.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        );
        if rc.is_err() || size == 0 {
            let _ = RegCloseKey(key);
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        let rc = RegQueryValueExW(
            key,
            PCWSTR(val.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(key);
        if rc.is_err() {
            return None;
        }

        buf.truncate(size as usize);
        // REG_SZ data is UTF-16; the stored length includes the terminator.
        let wide: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        Some(String::from_utf16_lossy(&wide))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_something_plausible_about_this_machine() {
        let m = MachineInfo::collect();
        assert!(!m.hostname.is_empty());
        assert!(!m.os.is_empty());
        assert_eq!(m.bark_version, crate::VERSION);
        assert!(m.cpu_threads >= 1);
    }

    #[cfg(windows)]
    #[test]
    fn os_description_names_windows_and_a_build() {
        let d = os_description();
        assert!(d.to_lowercase().contains("windows"), "got {d}");
        assert!(d.contains("build"), "got {d}");
    }

    #[cfg(windows)]
    #[test]
    fn missing_registry_values_return_none_rather_than_panicking() {
        assert_eq!(read_registry_string(r"SOFTWARE\NoSuchKeyForBark", "Nope"), None);
        assert_eq!(
            read_registry_string(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "NoSuchValue"),
            None
        );
    }

    #[test]
    fn machine_info_survives_a_json_round_trip() {
        let m = MachineInfo::collect();
        let j = serde_json::to_string(&m).unwrap();
        let back: MachineInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
