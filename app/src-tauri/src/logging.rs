//! The log file: `%LOCALAPPDATA%\Bilby\logs\bilby.log`, info level unless
//! `BILBY_LOG=debug`, rotated at 5 MB (one old file kept as `bilby.log.1`).
//!
//! Every line goes through the same scrubber as snapshot dumps, so the user
//! name, computer name, profile path and account SIDs never reach the file.
//! Bilby logs steps, statuses and timings; it never logs file hashes,
//! settings values or keys.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bilby_core::scrub::Scrubber;

/// Largest the log gets before it's rotated.
pub const MAX_BYTES: u64 = 5 * 1024 * 1024;

/// A log file that starts again once it reaches its limit, keeping the
/// previous one as `<name>.1`.
pub struct Rotating {
    path: PathBuf,
    file: File,
    size: u64,
    max: u64,
    scrub: Scrubber,
}

impl Rotating {
    /// Opens (or creates) `path` for appending.
    pub fn open(path: &Path, max: u64, scrub: Scrubber) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_owned(),
            file,
            size,
            max,
            scrub,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        let _ = std::fs::remove_file(&old);
        // Rust opens files with delete sharing on Windows, so the open file
        // can be renamed.
        std::fs::rename(&self.path, &old)?;
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

impl Write for Rotating {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = self.scrub.text(&String::from_utf8_lossy(buf));
        let len = text.len() as u64;
        if self.size > 0 && self.size + len > self.max {
            self.rotate()?;
        }
        self.file.write_all(text.as_bytes())?;
        self.size += len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Starts logging to the file. Does nothing if the folder can't be made:
/// a missing log never stops a scan.
pub fn init(scrub: Scrubber) {
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let dir = PathBuf::from(base).join("Bilby").join("logs");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let Ok(file) = Rotating::open(&dir.join("bilby.log"), MAX_BYTES, scrub) else {
        return;
    };
    let level = match std::env::var("BILBY_LOG").as_deref() {
        Ok("debug") => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(Mutex::new(file))
        .with_ansi(false)
        .with_target(false)
        .with_max_level(level)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_and_scrubs() {
        let dir = std::env::temp_dir().join(format!("bilby-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bilby.log");
        let scrub = Scrubber::new(&[r"C:\Users\alex"], Some("alex"), Some("DESKTOP-1"));
        let mut log = Rotating::open(&path, 100, scrub).unwrap();
        for _ in 0..5 {
            log.write_all(b"scan by alex on DESKTOP-1 in C:\\Users\\alex\\Temp\n")
                .unwrap();
        }
        log.flush().unwrap();
        let now = std::fs::read_to_string(&path).unwrap();
        let old = std::fs::read_to_string(dir.join("bilby.log.1")).unwrap();
        assert!(now.len() <= 100, "{}", now.len());
        assert_ne!(old, "");
        for text in [&now, &old] {
            assert!(
                !text.contains("alex") && !text.contains("DESKTOP-1"),
                "{text}"
            );
            assert!(text.contains("<user> on <computer> in %USERPROFILE%\\Temp"));
        }
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
