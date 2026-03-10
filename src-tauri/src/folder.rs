use crate::crypto;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const VAULT_MAGIC: &[u8; 8] = b"SECRLK\x01\x00";
const VAULT_EXT: &str = ".vault";

// Legacy constants (kept for backward compat detection)
const META_FILE: &str = ".securelock";

#[derive(Serialize, Deserialize)]
struct VaultHeader {
    version: u32,
    salt: Vec<u8>,
    verify_token: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_key: Option<Vec<u8>>,
    original_name: String,
    file_count: usize,
    total_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedFolder {
    pub path: String,
    pub is_locked: bool,
    pub file_count: usize,
    pub has_recovery: bool,
}

// ── Vault I/O helpers ────────────────────────────────────────────────────────

/// Set vault read-only to prevent accidental content modification.
fn set_readonly(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let mut perms = metadata.permissions();
    perms.set_readonly(true);
    fs::set_permissions(path, perms)
        .map_err(|e| format!("Failed to set read-only: {}", e))
}

/// Clear read-only so the app can delete the vault during unlock.
fn set_writable(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let mut perms = metadata.permissions();
    perms.set_readonly(false);
    fs::set_permissions(path, perms)
        .map_err(|e| format!("Failed to set writable: {}", e))
}

/// Read only the header JSON (efficient — stops before the ciphertext).
fn read_vault_header_only(vault_path: &Path) -> Result<VaultHeader, String> {
    let mut file = fs::File::open(vault_path)
        .map_err(|e| format!("Failed to open vault: {}", e))?;

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|_| "Failed to read vault magic".to_string())?;
    if &magic != VAULT_MAGIC {
        return Err("Not a valid SecureLock vault file".into());
    }

    let mut header_len_buf = [0u8; 4];
    file.read_exact(&mut header_len_buf)
        .map_err(|_| "Failed to read vault header length".to_string())?;
    let header_len = u32::from_le_bytes(header_len_buf) as usize;

    let mut header_bytes = vec![0u8; header_len];
    file.read_exact(&mut header_bytes)
        .map_err(|_| "Failed to read vault header".to_string())?;

    serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("Invalid vault header: {}", e))
}

/// Read the full vault — header + nonce + ciphertext — for decryption.
fn read_vault_full(
    vault_path: &Path,
) -> Result<(VaultHeader, [u8; crypto::NONCE_LEN], Vec<u8>), String> {
    let mut file = fs::File::open(vault_path)
        .map_err(|e| format!("Failed to open vault: {}", e))?;

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|_| "Failed to read vault magic".to_string())?;
    if &magic != VAULT_MAGIC {
        return Err("Not a valid SecureLock vault file".into());
    }

    let mut header_len_buf = [0u8; 4];
    file.read_exact(&mut header_len_buf)
        .map_err(|_| "Failed to read vault header length".to_string())?;
    let header_len = u32::from_le_bytes(header_len_buf) as usize;

    let mut header_bytes = vec![0u8; header_len];
    file.read_exact(&mut header_bytes)
        .map_err(|_| "Failed to read vault header".to_string())?;
    let header: VaultHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("Invalid vault header: {}", e))?;

    let mut nonce = [0u8; crypto::NONCE_LEN];
    file.read_exact(&mut nonce)
        .map_err(|_| "Failed to read vault nonce".to_string())?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)
        .map_err(|e| format!("Failed to read vault data: {}", e))?;

    Ok((header, nonce, ciphertext))
}

/// Reconstruct all files from a decrypted payload into `output_folder`.
fn reconstruct_files(
    output_folder: &Path,
    plaintext: &[u8],
    file_count: usize,
) -> Result<(), String> {
    let mut cursor = Cursor::new(plaintext);

    for _ in 0..file_count {
        let mut path_len_buf = [0u8; 4];
        cursor
            .read_exact(&mut path_len_buf)
            .map_err(|_| "Corrupted vault payload: failed to read path length".to_string())?;
        let path_len = u32::from_le_bytes(path_len_buf) as usize;

        let mut path_buf = vec![0u8; path_len];
        cursor
            .read_exact(&mut path_buf)
            .map_err(|_| "Corrupted vault payload: failed to read path".to_string())?;
        let rel_path =
            String::from_utf8(path_buf).map_err(|_| "Corrupted vault payload: invalid UTF-8 path".to_string())?;

        let mut data_len_buf = [0u8; 8];
        cursor
            .read_exact(&mut data_len_buf)
            .map_err(|_| "Corrupted vault payload: failed to read data length".to_string())?;
        let data_len = u64::from_le_bytes(data_len_buf) as usize;

        let mut data = vec![0u8; data_len];
        cursor
            .read_exact(&mut data)
            .map_err(|_| "Corrupted vault payload: failed to read file data".to_string())?;

        // Guard against path traversal attacks
        if rel_path.contains("..") {
            return Err(format!("Unsafe path in vault: '{}'", rel_path));
        }
        for component in Path::new(&rel_path).components() {
            match component {
                std::path::Component::Normal(_) => {}
                _ => return Err(format!("Unsafe path in vault: '{}'", rel_path)),
            }
        }

        let output_path = output_folder.join(&rel_path);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!("Failed to create directory '{}': {}", parent.display(), e)
            })?;
        }
        fs::write(&output_path, &data)
            .map_err(|e| format!("Failed to write '{}': {}", output_path.display(), e))?;
    }

    Ok(())
}

// ── Public API ───────────────────────────────────────────────────────────────

pub fn lock_folder(
    folder_path: &str,
    password: &str,
    master_key: Option<&[u8; 32]>,
) -> Result<ProtectedFolder, String> {
    let folder = Path::new(folder_path);
    if !folder.is_dir() {
        return Err(format!("'{}' is not a valid directory", folder_path));
    }

    let vault_path = PathBuf::from(format!("{}{}", folder_path, VAULT_EXT));
    if vault_path.exists() {
        return Err("A vault already exists for this folder".into());
    }

    // Collect all files (skip hidden files and symlinks)
    let file_paths: Vec<PathBuf> = WalkDir::new(folder)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && !e.file_type().is_symlink()
                && !e.file_name().to_str().map(|n| n.starts_with('.')).unwrap_or(false)
        })
        .map(|e| e.into_path())
        .collect();

    // Read all file contents up front (abort before touching disk if any read fails)
    let mut file_entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total_size: u64 = 0;
    for file_path in &file_paths {
        let relative = file_path
            .strip_prefix(folder)
            .map_err(|e| format!("Path error: {}", e))?;
        // Normalize separators to forward-slash for cross-platform portability
        let rel_str = relative.to_string_lossy().replace('\\', "/");
        let data = fs::read(file_path)
            .map_err(|e| format!("Failed to read '{}': {}", file_path.display(), e))?;
        total_size += data.len() as u64;
        file_entries.push((rel_str, data));
    }

    let file_count = file_entries.len();
    let original_name = folder
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("folder")
        .to_string();

    // Derive key and create crypto material
    let salt = crypto::generate_salt();
    let mut key = crypto::derive_key(password, &salt)?;
    let verify_token = crypto::create_verify_token(&key)?;
    let recovery_key = match master_key {
        Some(mk) => Some(crypto::wrap_key(mk, &key)?),
        None => None,
    };

    // Serialize payload: [path_len u32][path bytes][data_len u64][data bytes] × N
    let mut payload: Vec<u8> = Vec::new();
    for (rel_path, data) in &file_entries {
        let path_bytes = rel_path.as_bytes();
        payload.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(path_bytes);
        payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
        payload.extend_from_slice(data);
    }
    drop(file_entries); // free memory before encryption

    let has_recovery = recovery_key.is_some();
    let header = VaultHeader {
        version: 1,
        salt: salt.to_vec(),
        verify_token,
        recovery_key,
        original_name,
        file_count,
        total_size,
    };
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| format!("Header serialization error: {}", e))?;

    // Encrypt
    let nonce = crypto::generate_nonce();
    let ciphertext = crypto::encrypt_with_nonce(&key, &nonce, &payload)?;
    crypto::zeroize_key(&mut key);
    drop(payload);

    // Write to a temp file in the same parent directory, then atomically rename
    let parent = vault_path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    tmp.write_all(VAULT_MAGIC)
        .map_err(|e| format!("Write error: {}", e))?;
    tmp.write_all(&(header_json.len() as u32).to_le_bytes())
        .map_err(|e| format!("Write error: {}", e))?;
    tmp.write_all(&header_json)
        .map_err(|e| format!("Write error: {}", e))?;
    tmp.write_all(&nonce)
        .map_err(|e| format!("Write error: {}", e))?;
    tmp.write_all(&ciphertext)
        .map_err(|e| format!("Write error: {}", e))?;
    tmp.flush().map_err(|e| format!("Flush error: {}", e))?;
    tmp.persist(&vault_path)
        .map_err(|e| format!("Failed to save vault: {}", e))?;

    // Set vault read-only to prevent accidental modification/deletion
    let _ = set_readonly(&vault_path);

    // Delete original folder — vault is safely written first
    fs::remove_dir_all(folder).map_err(|e| {
        format!(
            "Vault created but failed to remove original folder (you may delete it manually): {}",
            e
        )
    })?;

    Ok(ProtectedFolder {
        path: vault_path.to_string_lossy().to_string(),
        is_locked: true,
        file_count,
        has_recovery,
    })
}

pub fn unlock_folder(vault_path: &str, password: &str) -> Result<ProtectedFolder, String> {
    let vault = Path::new(vault_path);
    if !vault.exists() {
        return Err("Vault file not found".into());
    }

    set_writable(vault)?;

    let (header, nonce, ciphertext) = read_vault_full(vault).map_err(|e| {
        let _ = set_readonly(vault);
        e
    })?;

    let salt: [u8; 32] = header
        .salt
        .clone()
        .try_into()
        .map_err(|_| "Invalid salt in vault".to_string())?;
    let mut key = crypto::derive_key(password, &salt).map_err(|e| {
        let _ = set_readonly(vault);
        e
    })?;

    if !crypto::verify_password(&key, &header.verify_token) {
        crypto::zeroize_key(&mut key);
        let _ = set_readonly(vault);
        return Err("Incorrect password".into());
    }

    let plaintext = crypto::decrypt_with_nonce(&key, &nonce, &ciphertext).map_err(|e| {
        crypto::zeroize_key(&mut key);
        let _ = set_readonly(vault);
        e
    })?;
    crypto::zeroize_key(&mut key);

    let output_str = vault_path
        .strip_suffix(VAULT_EXT)
        .ok_or("Path does not have .vault extension")?;
    let output_folder = Path::new(output_str);

    if output_folder.exists() {
        let _ = set_readonly(vault);
        return Err(format!(
            "Cannot unlock: '{}' already exists",
            output_folder.display()
        ));
    }

    let file_count = header.file_count;
    let parent = vault.parent().unwrap_or(Path::new("."));

    // Reconstruct into a temp dir first — if anything fails, vault stays intact
    let tmp_dir = tempfile::Builder::new()
        .prefix(".slk_tmp_")
        .tempdir_in(parent)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;

    reconstruct_files(tmp_dir.path(), &plaintext, file_count).map_err(|e| {
        // tmp_dir auto-cleans on drop
        let _ = set_readonly(vault);
        e
    })?;

    // Atomically move temp dir to final location
    fs::rename(tmp_dir.keep(), output_folder)
        .map_err(|e| format!("Failed to restore folder: {}", e))?;

    fs::remove_file(vault)
        .map_err(|e| format!("Folder restored but failed to delete vault: {}", e))?;

    Ok(ProtectedFolder {
        path: output_str.to_string(),
        is_locked: false,
        file_count,
        has_recovery: false,
    })
}

pub fn unlock_folder_with_master_key(
    vault_path: &str,
    master_key: &[u8; 32],
) -> Result<ProtectedFolder, String> {
    let vault = Path::new(vault_path);
    if !vault.exists() {
        return Err("Vault file not found".into());
    }

    set_writable(vault)?;

    let (header, nonce, ciphertext) = read_vault_full(vault).map_err(|e| {
        let _ = set_readonly(vault);
        e
    })?;

    let wrapped = header.recovery_key.ok_or_else(|| {
        let _ = set_readonly(vault);
        "No recovery key found in this vault".to_string()
    })?;

    let mut folder_key = crypto::unwrap_key(master_key, &wrapped).map_err(|e| {
        let _ = set_readonly(vault);
        e
    })?;

    if !crypto::verify_password(&folder_key, &header.verify_token) {
        crypto::zeroize_key(&mut folder_key);
        let _ = set_readonly(vault);
        return Err("Master password verification failed".into());
    }

    let plaintext =
        crypto::decrypt_with_nonce(&folder_key, &nonce, &ciphertext).map_err(|e| {
            crypto::zeroize_key(&mut folder_key);
            let _ = set_readonly(vault);
            e
        })?;
    crypto::zeroize_key(&mut folder_key);

    let output_str = vault_path
        .strip_suffix(VAULT_EXT)
        .ok_or("Path does not have .vault extension")?;
    let output_folder = Path::new(output_str);

    if output_folder.exists() {
        let _ = set_readonly(vault);
        return Err(format!(
            "Cannot unlock: '{}' already exists",
            output_folder.display()
        ));
    }

    let file_count = header.file_count;
    let parent = vault.parent().unwrap_or(Path::new("."));

    let tmp_dir = tempfile::Builder::new()
        .prefix(".slk_tmp_")
        .tempdir_in(parent)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;

    reconstruct_files(tmp_dir.path(), &plaintext, file_count).map_err(|e| {
        let _ = set_readonly(vault);
        e
    })?;

    fs::rename(tmp_dir.keep(), output_folder)
        .map_err(|e| format!("Failed to restore folder: {}", e))?;

    fs::remove_file(vault)
        .map_err(|e| format!("Folder restored but failed to delete vault: {}", e))?;

    Ok(ProtectedFolder {
        path: output_str.to_string(),
        is_locked: false,
        file_count,
        has_recovery: false,
    })
}

pub fn is_locked(path: &str) -> bool {
    let p = Path::new(path);
    // New format: .vault file
    if path.ends_with(VAULT_EXT) && p.is_file() {
        return true;
    }
    // Legacy format: directory with .securelock manifest
    if p.is_dir() && p.join(META_FILE).exists() {
        return true;
    }
    false
}

pub fn is_legacy_locked(path: &str) -> bool {
    let p = Path::new(path);
    p.is_dir() && p.join(META_FILE).exists()
}

pub fn has_recovery_key(path: &str) -> bool {
    if path.ends_with(VAULT_EXT) {
        if let Ok(header) = read_vault_header_only(Path::new(path)) {
            return header.recovery_key.is_some();
        }
        return false;
    }
    if is_legacy_locked(path) {
        return legacy::has_recovery_key(path);
    }
    false
}

pub fn get_file_count(path: &str) -> usize {
    if path.ends_with(VAULT_EXT) {
        if let Ok(header) = read_vault_header_only(Path::new(path)) {
            return header.file_count;
        }
        return 0;
    }
    if is_legacy_locked(path) {
        return legacy::get_locked_file_count(path);
    }
    count_files(path)
}

pub fn unlock_folder_legacy(folder_path: &str, password: &str) -> Result<ProtectedFolder, String> {
    legacy::unlock_folder(folder_path, password)
}

pub fn unlock_folder_legacy_with_master_key(
    folder_path: &str,
    master_key: &[u8; 32],
) -> Result<ProtectedFolder, String> {
    legacy::unlock_with_master_key(folder_path, master_key)
}

pub fn count_files(folder_path: &str) -> usize {
    WalkDir::new(folder_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && !e.file_name().to_str().map(|n| n.starts_with('.')).unwrap_or(false)
        })
        .count()
}

// ── Legacy format support (read-only — for unlocking old .securelock folders) ──

mod legacy {
    use super::*;
    use crate::crypto;

    #[derive(Serialize, Deserialize)]
    struct FolderMeta {
        salt: Vec<u8>,
        verify_token: Vec<u8>,
        files: Vec<FileMeta>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_key: Option<Vec<u8>>,
    }

    #[derive(Serialize, Deserialize)]
    struct FileMeta {
        original_name: String,
        locked_name: String,
        relative_path: String,
    }

    fn read_meta(folder_path: &str) -> Result<(FolderMeta, PathBuf), String> {
        let folder = Path::new(folder_path);
        let meta_path = folder.join(META_FILE);
        if !meta_path.exists() {
            return Err("Folder is not locked (no .securelock metadata found)".into());
        }
        let meta_json = fs::read_to_string(&meta_path)
            .map_err(|e| format!("Failed to read metadata: {}", e))?;
        let meta: FolderMeta = serde_json::from_str(&meta_json)
            .map_err(|e| format!("Invalid metadata: {}", e))?;
        Ok((meta, meta_path))
    }

    fn decrypt_files(folder: &Path, key: &[u8; 32], files: &[FileMeta]) -> Result<(), String> {
        for file_meta in files {
            let locked_path = folder
                .join(&file_meta.relative_path)
                .with_file_name(&file_meta.locked_name);
            if !locked_path.exists() {
                continue;
            }
            let encrypted = fs::read(&locked_path)
                .map_err(|e| format!("Failed to read '{}': {}", locked_path.display(), e))?;
            let plaintext = crypto::decrypt(key, &encrypted)?;
            let original_path = locked_path.with_file_name(&file_meta.original_name);
            fs::write(&original_path, &plaintext)
                .map_err(|e| format!("Failed to write '{}': {}", original_path.display(), e))?;
            fs::remove_file(&locked_path)
                .map_err(|e| format!("Failed to remove '{}': {}", locked_path.display(), e))?;
        }
        Ok(())
    }

    pub fn unlock_folder(folder_path: &str, password: &str) -> Result<ProtectedFolder, String> {
        let (meta, meta_path) = read_meta(folder_path)?;
        let folder = Path::new(folder_path);
        let salt: [u8; 32] = meta
            .salt
            .clone()
            .try_into()
            .map_err(|_| "Invalid salt in metadata".to_string())?;
        let key = crypto::derive_key(password, &salt)?;
        if !crypto::verify_password(&key, &meta.verify_token) {
            return Err("Incorrect password".into());
        }
        let file_count = meta.files.len();
        decrypt_files(folder, &key, &meta.files)?;
        fs::remove_file(&meta_path)
            .map_err(|e| format!("Failed to remove metadata: {}", e))?;
        Ok(ProtectedFolder {
            path: folder_path.to_string(),
            is_locked: false,
            file_count,
            has_recovery: false,
        })
    }

    pub fn unlock_with_master_key(
        folder_path: &str,
        master_key: &[u8; 32],
    ) -> Result<ProtectedFolder, String> {
        let (meta, meta_path) = read_meta(folder_path)?;
        let folder = Path::new(folder_path);
        let wrapped = meta
            .recovery_key
            .ok_or("No recovery key found for this folder")?;
        let folder_key = crypto::unwrap_key(master_key, &wrapped)?;
        if !crypto::verify_password(&folder_key, &meta.verify_token) {
            return Err("Master password verification failed".into());
        }
        let file_count = meta.files.len();
        decrypt_files(folder, &folder_key, &meta.files)?;
        fs::remove_file(&meta_path)
            .map_err(|e| format!("Failed to remove metadata: {}", e))?;
        Ok(ProtectedFolder {
            path: folder_path.to_string(),
            is_locked: false,
            file_count,
            has_recovery: false,
        })
    }

    pub fn has_recovery_key(folder_path: &str) -> bool {
        if let Ok((meta, _)) = read_meta(folder_path) {
            return meta.recovery_key.is_some();
        }
        false
    }

    pub fn get_locked_file_count(folder_path: &str) -> usize {
        let meta_path = Path::new(folder_path).join(META_FILE);
        if let Ok(json) = fs::read_to_string(&meta_path) {
            if let Ok(meta) = serde_json::from_str::<FolderMeta>(&json) {
                return meta.files.len();
            }
        }
        0
    }
}
