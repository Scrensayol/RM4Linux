//! Secure storage for `.ROBLOSECURITY` cookies.
//!
//! Two backends:
//! 1. **File-based AES-256-GCM** — encrypts an `AccountStore` JSON blob with a
//!    key derived from a user-supplied master password (PBKDF2-like via SHA-256
//!    stretching). The encrypted payload is stored as a single `.dat` file.
//! 2. **Windows Credential Manager** — stores each cookie individually via the
//!    `keyring` crate, keyed by Roblox user ID.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::CoreError;
use crate::models::AccountStore;

// ---------------------------------------------------------------------------
// File-based AES-256-GCM encryption
// ---------------------------------------------------------------------------

/// Derive a 256-bit key from a password using iterated SHA-256.
/// This is intentionally simple; swap for `argon2` if you want stronger KDF.
fn derive_key(password: &str) -> [u8; 32] {
    let mut hash = Sha256::digest(password.as_bytes());
    for _ in 0..100_000 {
        hash = Sha256::digest(hash);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Encrypt the `AccountStore` to bytes: `nonce (12) || ciphertext`.
pub fn encrypt_store(store: &AccountStore, password: &str) -> Result<Vec<u8>, CoreError> {
    let plaintext = serde_json::to_vec(store)?;
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt bytes produced by `encrypt_store` back into an `AccountStore`.
pub fn decrypt_store(data: &[u8], password: &str) -> Result<AccountStore, CoreError> {
    if data.len() < 13 {
        return Err(CoreError::Crypto("encrypted data too short".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| {
            // A GCM auth failure means the key is wrong OR the ciphertext was
            // damaged. We genuinely can't tell which from the tag alone, so the
            // message must not blame the password outright (see load_encrypted,
            // which tries the backup before this surfaces to the user).
            CoreError::Crypto(
                "could not decrypt the account store: wrong master password, or the file is corrupted"
                    .into(),
            )
        })?;

    let store: AccountStore = serde_json::from_slice(&plaintext)?;
    Ok(store)
}

/// Save the encrypted store to a file using an atomic write (temp + fsync +
/// rename) that also preserves the previous good copy as `<path>.bak`. This is
/// what makes overlapping/torn saves impossible; see [`crate::storage`].
pub fn save_encrypted(
    path: &Path,
    store: &AccountStore,
    password: &str,
) -> Result<(), CoreError> {
    let bytes = encrypt_store(store, password)?;
    crate::storage::atomic_write(path, &bytes)?;
    Ok(())
}

/// Load and decrypt the store from a file, transparently recovering from the
/// backup if the primary file fails to authenticate.
///
/// If the primary `<path>` won't decrypt but `<path>.bak` decrypts with the
/// same password, the primary was corrupted (e.g. a torn write from an older
/// build): we return the backup's contents and self-heal the primary from it.
/// Only when *both* fail do we surface the decrypt error — at which point a
/// wrong password is the likely explanation.
pub fn load_encrypted(path: &Path, password: &str) -> Result<AccountStore, CoreError> {
    let bytes = std::fs::read(path)?;
    let primary_err = match decrypt_store(&bytes, password) {
        Ok(store) => return Ok(store),
        Err(e) => e,
    };

    let backup = crate::storage::backup_path(path);
    if let Ok(backup_bytes) = std::fs::read(&backup) {
        if let Ok(store) = decrypt_store(&backup_bytes, password) {
            tracing::warn!(
                "Primary account store at {} failed to decrypt; recovered from backup {}",
                path.display(),
                backup.display()
            );
            // Restore the good copy as the primary WITHOUT touching the backup
            // (atomic_write would copy the corrupt primary over our only good
            // backup first — atomic_swap leaves the backup intact).
            let _ = crate::storage::atomic_swap(path, &backup_bytes);
            return Ok(store);
        }
    }

    Err(primary_err)
}

// ---------------------------------------------------------------------------
// Windows Credential Manager backend
// ---------------------------------------------------------------------------

const SERVICE_NAME: &str = "RM-Rust";

/// Store a single cookie in the OS credential store.
pub fn credential_store(user_id: u64, cookie: &str) -> Result<(), CoreError> {
    let entry = keyring::Entry::new(SERVICE_NAME, &user_id.to_string())
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    entry
        .set_password(cookie)
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    Ok(())
}

/// Retrieve a cookie from the OS credential store.
pub fn credential_load(user_id: u64) -> Result<String, CoreError> {
    let entry = keyring::Entry::new(SERVICE_NAME, &user_id.to_string())
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    entry
        .get_password()
        .map_err(|e| CoreError::Keyring(e.to_string()))
}

/// Delete a cookie from the OS credential store.
pub fn credential_delete(user_id: u64) -> Result<(), CoreError> {
    let entry = keyring::Entry::new(SERVICE_NAME, &user_id.to_string())
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    entry
        .delete_credential()
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Cookie encryption helpers (for in-memory Account struct serialization)
// ---------------------------------------------------------------------------

/// Encrypt a single cookie string, returning a Base64 blob.
pub fn encrypt_cookie(cookie: &str, password: &str) -> Result<String, CoreError> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, cookie.as_bytes())
        .map_err(|e| CoreError::Crypto(e.to_string()))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(B64.encode(&combined))
}

/// Decrypt a Base64-encoded cookie blob.
pub fn decrypt_cookie(encoded: &str, password: &str) -> Result<String, CoreError> {
    let data = B64
        .decode(encoded)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    if data.len() < 13 {
        return Err(CoreError::Crypto("encrypted cookie too short".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CoreError::Crypto("cookie decryption failed".into()))?;

    String::from_utf8(plaintext).map_err(|e| CoreError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Account;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ram_crypto_{}_{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("accounts.dat")
    }

    fn store_with(n: u64) -> AccountStore {
        let mut s = AccountStore::default();
        for i in 0..n {
            s.accounts.push(Account::new(i, format!("user{i}"), format!("User {i}")));
        }
        s
    }

    #[test]
    fn round_trips_through_disk() {
        let p = scratch("roundtrip");
        let store = store_with(3);
        save_encrypted(&p, &store, "hunter2").unwrap();
        let loaded = load_encrypted(&p, "hunter2").unwrap();
        assert_eq!(loaded.accounts.len(), 3);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let p = scratch("wrongpw");
        save_encrypted(&p, &store_with(1), "correct").unwrap();
        assert!(load_encrypted(&p, "incorrect").is_err());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn recovers_and_self_heals_from_backup_when_primary_corrupt() {
        let p = scratch("recover");
        // First save: primary only. Second save: primary=v2, backup=v1.
        save_encrypted(&p, &store_with(1), "pw").unwrap();
        save_encrypted(&p, &store_with(2), "pw").unwrap();

        // Simulate a torn write landing on the primary (what the old
        // non-atomic concurrent path produced).
        std::fs::write(&p, b"this is not a valid aes-gcm blob at all").unwrap();

        // Load transparently recovers the last good copy (v1, the backup).
        let recovered = load_encrypted(&p, "pw").unwrap();
        assert_eq!(recovered.accounts.len(), 1);

        // ...and self-heals the primary so the next load needs no backup.
        let healed_bytes = std::fs::read(&p).unwrap();
        assert_eq!(decrypt_store(&healed_bytes, "pw").unwrap().accounts.len(), 1);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn concurrent_writers_never_corrupt_the_file() {
        use std::sync::Arc;
        use std::thread;

        let p = Arc::new(scratch("concurrent"));
        save_encrypted(&p, &store_with(1), "pw").unwrap();

        let mut handles = Vec::new();
        for w in 0..8u64 {
            let p = Arc::clone(&p);
            handles.push(thread::spawn(move || {
                for _ in 0..25 {
                    let _ = save_encrypted(&p, &store_with(w + 1), "pw");
                }
            }));
        }

        // Hammer reads while writers race. Atomic rename means every read sees
        // a complete file; load_encrypted falls back to the backup if it ever
        // catches a primary from a different-length write mid-swap.
        for _ in 0..200 {
            assert!(
                load_encrypted(&p, "pw").is_ok(),
                "a concurrent write produced an unreadable file"
            );
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(load_encrypted(&p, "pw").is_ok());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
