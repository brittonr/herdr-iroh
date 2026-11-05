//! Persistent 32-byte iroh secret keys. Mode `0600` on Unix.

use std::path::{Path, PathBuf};

use anyhow::Context;
use iroh::SecretKey;

pub const SECRET_FILE: &str = "secret_key";

#[must_use]
pub fn secret_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SECRET_FILE)
}

/// Load a key, or create one when the file is absent.
///
/// # Errors
///
/// Returns an error when the file is not 32 bytes or cannot be written.
pub fn load_or_create(path: &Path) -> anyhow::Result<SecretKey> {
    if path.exists() {
        return load(path);
    }
    let key = SecretKey::generate();
    write_new(path, &key)?;
    Ok(key)
}

/// Load an existing key.
///
/// # Errors
///
/// Returns an error when the file is missing or the wrong size.
pub fn load(path: &Path) -> anyhow::Result<SecretKey> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} is {} bytes; expected 32", path.display(), bytes.len()))?;
    Ok(SecretKey::from_bytes(&array))
}

/// Create a key. Refuses to replace an existing file unless `force` is set.
///
/// # Errors
///
/// Returns an error when the file exists and `force` is false, or the write fails.
pub fn generate(path: &Path, force: bool) -> anyhow::Result<SecretKey> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; run keygen --force to rotate it (allowlists that name this endpoint id will stop working)",
            path.display()
        );
    }
    let key = SecretKey::generate();
    write_new(path, &key)?;
    Ok(key)
}

fn write_new(path: &Path, key: &SecretKey) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(&key.to_bytes())?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Endpoint id string for an allowlist. This is the public half of the key.
#[must_use]
pub fn endpoint_id(key: &SecretKey) -> String {
    key.public().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip_is_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret_key");
        let created = generate(&path, false).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(created.to_bytes(), loaded.to_bytes());
        assert!(generate(&path, false).is_err());
        let rotated = generate(&path, true).unwrap();
        assert_ne!(rotated.to_bytes(), created.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
