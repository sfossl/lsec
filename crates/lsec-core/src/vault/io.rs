use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use super::envelope::{seal, unseal};
use super::error::VaultError;
use super::format::CipherSuite;
use crate::config::{
    POSIX_DIR_PERMISSIONS, POSIX_FILE_PERMISSIONS, SecurityConfig,
};
use crate::crypto::generate_salt;
use crate::memguard::ProtectedBuffer;

fn generate_temp_path(target: &Path) -> Result<std::path::PathBuf, VaultError> {
    let random_bytes = generate_salt()?;
    let hex_suffix = hex_encode(&random_bytes[0..8]);
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    let temp_name = format!(".{}.tmp.{}", file_name, hex_suffix);
    Ok(match target.parent() {
        Some(parent) => parent.join(temp_name),
        None => std::path::PathBuf::from(temp_name),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn seal_to_file<P: AsRef<Path>>(
    path: P,
    plaintext: &[u8],
    passphrase: &[u8],
    config: &SecurityConfig,
    cipher: CipherSuite,
) -> Result<(), VaultError> {
    let target_path = path.as_ref();
    let sealed_payload = seal(plaintext, passphrase, config, cipher)?;

    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                builder.mode(POSIX_DIR_PERMISSIONS);
                builder.create(parent)?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(parent)?;
            }
        }
    }

    let temp_path = generate_temp_path(target_path)?;

    let write_result = (|| -> Result<(), VaultError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(POSIX_FILE_PERMISSIONS);
        }

        let mut file = options.open(&temp_path)?;
        file.write_all(&sealed_payload)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&temp_path, target_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(VaultError::Io(e));
    }

    Ok(())
}

pub fn seal_to_file_default<P: AsRef<Path>>(
    path: P,
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<(), VaultError> {
    seal_to_file(
        path,
        plaintext,
        passphrase,
        &SecurityConfig::default(),
        CipherSuite::ChaCha20Poly1305,
    )
}

pub fn unseal_from_file<P: AsRef<Path>>(
    path: P,
    passphrase: &[u8],
) -> Result<ProtectedBuffer, VaultError> {
    let bytes = fs::read(path.as_ref())?;
    unseal(&bytes, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fast_config() -> SecurityConfig {
        SecurityConfig::builder()
            .argon2_memory_kib(1024)
            .argon2_iterations(1)
            .argon2_parallelism(1)
            .build()
    }

    #[test]
    fn test_file_seal_and_unseal_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("lsec_test_{}", std::process::id()));
        let vault_file = temp_dir.join("test_vault.db");
        let secret = b"my-offline-credentials-database";
        let pass = b"super-strong-user-passphrase";
        let config = test_fast_config();

        let seal_res = seal_to_file(
            &vault_file,
            secret,
            pass,
            &config,
            CipherSuite::ChaCha20Poly1305,
        );
        assert!(seal_res.is_ok());
        assert!(vault_file.exists());

        let unsealed = unseal_from_file(&vault_file, pass).expect("unseal file ok");
        assert_eq!(&unsealed[..], secret);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_atomic_overwrite_preserves_validity() {
        let temp_dir = std::env::temp_dir().join(format!("lsec_test_atomic_{}", std::process::id()));
        let vault_file = temp_dir.join("atomic_vault.db");
        let pass = b"passphrase-v1";
        let config = test_fast_config();

        seal_to_file(&vault_file, b"version-1", pass, &config, CipherSuite::ChaCha20Poly1305).expect("v1 ok");
        assert_eq!(&unseal_from_file(&vault_file, pass).unwrap()[..], b"version-1");

        // atomic update
        seal_to_file(&vault_file, b"version-2", pass, &config, CipherSuite::ChaCha20Poly1305).expect("v2 ok");
        assert_eq!(&unseal_from_file(&vault_file, pass).unwrap()[..], b"version-2");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = std::env::temp_dir().join(format!("lsec_test_perm_{}", std::process::id()));
        let vault_file = temp_dir.join("perm_vault.db");
        let pass = b"passphrase";
        let config = test_fast_config();

        seal_to_file(&vault_file, b"permission-test", pass, &config, CipherSuite::ChaCha20Poly1305).expect("ok");

        let metadata = fs::metadata(&vault_file).expect("metadata ok");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, POSIX_FILE_PERMISSIONS);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unseal_nonexistent_file_fails() {
        let fake_path = std::path::PathBuf::from("/nonexistent/vault/path.db");
        let res = unseal_from_file(&fake_path, b"pass");
        assert!(matches!(res, Err(VaultError::Io(_))));
    }

    #[test]
    fn test_unseal_truncated_disk_file_fails() {
        let temp_dir = std::env::temp_dir().join(format!("lsec_test_trunc_{}", std::process::id()));
        let vault_file = temp_dir.join("truncated.db");
        fs::create_dir_all(&temp_dir).expect("dir ok");
        fs::write(&vault_file, b"too-short-data").expect("write ok");

        let res = unseal_from_file(&vault_file, b"pass");
        assert!(matches!(res, Err(VaultError::HeaderTooShort)));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unseal_corrupted_disk_payload_fails() {
        let temp_dir = std::env::temp_dir().join(format!("lsec_test_corrupt_{}", std::process::id()));
        let vault_file = temp_dir.join("corrupted.db");
        let pass = b"passphrase";
        let config = test_fast_config();

        seal_to_file(&vault_file, b"valid-payload", pass, &config, CipherSuite::ChaCha20Poly1305).expect("ok");

        let mut data = fs::read(&vault_file).expect("read ok");
        let last_idx = data.len() - 1;
        data[last_idx] ^= 0x55;
        fs::write(&vault_file, &data).expect("corrupt write ok");

        let res = unseal_from_file(&vault_file, pass);
        assert!(matches!(res, Err(VaultError::Crypto(_))));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_subsequent_write_cleans_and_succeeds() {
        let temp_dir = std::env::temp_dir().join(format!("lsec_test_abandoned_{}", std::process::id()));
        let vault_file = temp_dir.join("clean.db");
        let pass = b"passphrase";
        let config = test_fast_config();

        fs::create_dir_all(&temp_dir).expect("dir ok");
        // write an abandoned temp file in same directory
        let abandoned_temp = temp_dir.join(".clean.db.tmp.deadbeef");
        fs::write(&abandoned_temp, b"stale-data").expect("write stale ok");

        seal_to_file(&vault_file, b"fresh-data", pass, &config, CipherSuite::ChaCha20Poly1305).expect("seal ok");
        let unsealed = unseal_from_file(&vault_file, pass).expect("unseal ok");
        assert_eq!(&unsealed[..], b"fresh-data");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
