//! Streaming SHA-256 of files.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Files bigger than this aren't hashed (installers, disk images). Their
/// hash would be slow to get and rarely useful for Bilby's checks.
pub const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;

const BUFFER: usize = 1024 * 1024;

/// Lower-case hex SHA-256 of a file, or `Ok(None)` if it's over
/// [`MAX_HASH_BYTES`]. Reads in 1 MiB chunks.
pub fn sha256_file(path: &Path) -> io::Result<Option<String>> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > MAX_HASH_BYTES {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUFFER];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some(hex(&hasher.finalize())))
}

/// Lower-case hex of some bytes.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
