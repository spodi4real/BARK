//! BARK.exe — the one program installed on every BARK computer.
//!
//! Started with no options it opens the BARK window. If BARK has not been
//! installed as a service on this computer, the window runs the BARK node
//! itself ("standalone" mode), with its own identity kept in the user's
//! profile; installation and the service mode come in a later milestone.
//!
//! Options:
//!   --profile <name>   run a separate standalone BARK with its own identity,
//!                      so two BARK nodes can be tried on one computer

#![windows_subsystem = "windows"]

mod app;
mod dialogs;
mod win;

use bark_node::NodeDirs;
use std::path::PathBuf;
use std::sync::OnceLock;

static DIRS: OnceLock<NodeDirs> = OnceLock::new();

/// The folder this BARK's node keeps its files in.
pub fn node_dirs_hint() -> PathBuf {
    DIRS.get().map(|d| d.root().to_path_buf()).unwrap_or_default()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut profile = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                profile = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            other => {
                win::error_box(None, &format!("Unknown option \"{other}\".\n\nBARK.exe accepts: --profile <name>"));
                std::process::exit(2);
            }
        }
        i += 1;
    }

    bark_core::clock::init();
    let dirs = NodeDirs::standalone(&profile);
    let _ = dirs.ensure();
    bark_core::logging::init_in(&dirs.logs(), bark_core::logging::Component::Gui, false);
    let _ = DIRS.set(dirs.clone());

    // One BARK window per identity. A second copy with the same identity would
    // sign in to the server and knock the first one off, over and over.
    if !single_instance(&profile) {
        return;
    }

    let suffix = if profile.is_empty() { String::new() } else { format!("  [profile {profile}]") };
    let code = app::run(move |sink| bark_node::start(dirs, sink), &suffix);
    std::process::exit(code);
}

/// Returns false, after bringing the existing window forward, if this profile
/// is already open.
fn single_instance(profile: &str) -> bool {
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE};

    let name = win::Wide::new(&format!("Local\\BARK.Standalone.{}", if profile.is_empty() { "default" } else { profile }));
    unsafe {
        let handle = CreateMutexW(None, true, name.pcwstr());
        if handle.is_ok() && GetLastError() == ERROR_ALREADY_EXISTS {
            let class = win::Wide::new("BARK.MainWindow");
            if let Ok(existing) = FindWindowW(class.pcwstr(), windows::core::PCWSTR::null()) {
                let _ = ShowWindow(existing, SW_RESTORE);
                let _ = SetForegroundWindow(existing);
            }
            return false;
        }
        // The handle is deliberately leaked: the mutex must live exactly as
        // long as this process, and the system releases it when we exit.
        std::mem::forget(handle);
    }
    true
}
