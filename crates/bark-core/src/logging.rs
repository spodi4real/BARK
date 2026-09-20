//! Diagnostic logging.
//!
//! Distinct from the audit log. This is the engineer-facing trace used when
//! something misbehaves; the audit log is the operator-facing record of who did
//! what. They have different retention, different formats and different rules
//! about what may be written.
//!
//! **Never logged, anywhere, at any level:** keystrokes, clipboard contents,
//! screen contents, file contents, private keys, session keys, pairing codes or
//! passwords. Where a value must be identifiable in a trace, log a short prefix
//! of its hash instead.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::EnvFilter;

/// Which executable is writing, so one folder of logs stays readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Service,
    Agent,
    Gui,
    Server,
    Tool,
}

impl Component {
    fn file_stem(self) -> &'static str {
        match self {
            Component::Service => "service",
            Component::Agent => "agent",
            Component::Gui => "gui",
            Component::Server => "server",
            Component::Tool => "tool",
        }
    }
}

/// Keeps one log file open, rolling it over once it grows past a limit and
/// keeping a small number of previous files.
///
/// A dedicated implementation rather than a rotation crate because the
/// behaviour that matters here is narrow and worth being sure of: a service
/// that runs for months must never fill the system drive, and a log that
/// rotates mid-incident must not lose the lines that explain it.
struct RollingFile {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    max_bytes: u64,
    keep: usize,
}

impl RollingFile {
    fn new(path: PathBuf, max_bytes: u64, keep: usize) -> Self {
        let written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        RollingFile { path, file: None, written, max_bytes, keep }
    }

    fn open(&mut self) -> std::io::Result<&mut File> {
        if self.file.is_none() {
            if let Some(dir) = self.path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let f = OpenOptions::new().create(true).append(true).open(&self.path)?;
            self.written = f.metadata().map(|m| m.len()).unwrap_or(0);
            self.file = Some(f);
        }
        Ok(self.file.as_mut().expect("just opened"))
    }

    fn roll(&mut self) {
        self.file = None;
        // service.4.log is dropped, 3 becomes 4, and so on down to the live file.
        for i in (1..self.keep).rev() {
            let from = self.numbered(i);
            let to = self.numbered(i + 1);
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }
        let _ = std::fs::rename(&self.path, self.numbered(1));
        self.written = 0;
    }

    fn numbered(&self, n: usize) -> PathBuf {
        let stem = self.path.file_stem().and_then(|s| s.to_str()).unwrap_or("bark");
        self.path.with_file_name(format!("{stem}.{n}.log"))
    }
}

impl Write for RollingFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written + buf.len() as u64 > self.max_bytes {
            self.roll();
        }
        let n = self.open()?.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

struct SharedWriter(std::sync::Arc<Mutex<RollingFile>>);

impl Clone for SharedWriter {
    fn clone(&self) -> Self {
        SharedWriter(self.0.clone())
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.lock() {
            Ok(mut g) => g.write(buf),
            // A poisoned lock means a logging thread panicked. Dropping the line
            // is better than panicking again inside the logger.
            Err(_) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.0.lock() {
            Ok(mut g) => g.flush(),
            Err(_) => Ok(()),
        }
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Initialises logging for a component.
///
/// `console` adds stderr output, which the GUI and the command-line tools want
/// but a service does not. Returns quietly if logging is already initialised, so
/// tests and repeated calls are harmless.
pub fn init(component: Component, console: bool) {
    init_in(&crate::paths::log_dir(), component, console)
}

pub fn init_in(dir: &Path, component: Component, console: bool) {
    // BARK_LOG overrides the level, e.g. BARK_LOG=bark_media=trace,info
    let filter = EnvFilter::try_from_env("BARK_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,bark_net=info,bark_media=info"));

    let path = dir.join(format!("{}.log", component.file_stem()));
    let writer = SharedWriter(std::sync::Arc::new(Mutex::new(RollingFile::new(
        path,
        8 * 1024 * 1024,
        4,
    ))));

    let timer = tracing_subscriber::fmt::time::UtcTime::new(
        time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
        ),
    );

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_timer(timer)
        .with_target(true)
        .with_level(true)
        .with_ansi(false)
        .with_thread_names(true);

    let result = if console {
        builder.with_writer(move || -> Box<dyn Write + Send> {
            Box::new(TeeWriter {
                a: writer.clone(),
                b: std::io::stderr(),
            })
        })
        .try_init()
    } else {
        builder.with_writer(writer).try_init()
    };

    if result.is_ok() {
        tracing::info!(
            component = ?component,
            version = crate::VERSION,
            protocol = crate::PROTOCOL_VERSION,
            "BARK starting"
        );
    }
}

struct TeeWriter<A: Write, B: Write> {
    a: A,
    b: B,
}

impl<A: Write, B: Write> Write for TeeWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.a.write(buf)?;
        let _ = self.b.write_all(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let _ = self.b.flush();
        self.a.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bark-log-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rolls_over_when_the_file_gets_too_big_and_keeps_history() {
        let dir = tempdir("roll");
        let path = dir.join("service.log");
        let mut rf = RollingFile::new(path.clone(), 100, 3);

        for _ in 0..40 {
            rf.write_all(b"0123456789").unwrap();
        }
        rf.flush().unwrap();
        drop(rf);

        assert!(path.exists(), "live log should exist");
        assert!(dir.join("service.1.log").exists(), "one generation back");
        assert!(dir.join("service.2.log").exists(), "two generations back");
        // keep = 3, so nothing beyond .3 is retained.
        assert!(!dir.join("service.4.log").exists(), "history is bounded");

        let live = std::fs::metadata(&path).unwrap().len();
        assert!(live <= 100, "live log {live} exceeded its limit");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn appends_to_an_existing_log_rather_than_truncating_it() {
        let dir = tempdir("append");
        let path = dir.join("service.log");
        std::fs::write(&path, b"previous run\n").unwrap();

        let mut rf = RollingFile::new(path.clone(), 1024 * 1024, 3);
        rf.write_all(b"this run\n").unwrap();
        rf.flush().unwrap();
        drop(rf);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("previous run"), "earlier lines were lost");
        assert!(contents.contains("this run"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
