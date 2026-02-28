use crate::crypto;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const LOCKED_EXT: &str = ".locked";
const META_FILE: &str = ".securelock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderMeta {
    pub salt: Vec<u8>,
    pub verify_token: Vec<u8>,
    pub files: Vec<FileMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub original_name: String,
    pub locked_name: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedFolder {
    pub path: String,
    pub is_locked: bool,
    pub file_count: usize,
    pub has_recovery: bool,
}

pub fn lock_folder(folder_path: &str, password: &str, master_key: Option<&[u8; 32]>) -> Result<ProtectedFolder, String> {
    let folder = Path::new(folder_path);
    if !folder.is_dir() {
        return Err(format!("'{}' is not a valid directory", folder_path));
    }
    let meta_path = folder.join(META_FILE);
    if meta_path.exists() {
        return Err("Folder is already locked".into());
    }
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(password, &salt)?;
    let verify_token = crypto::create_verify_token(&key)?;
    let recovery_key = match master_key {
        Some(mk) => Some(crypto::wrap_key(mk, &key)?),
        None => None,
    };
    let files: Vec<PathBuf> = WalkDir::new(folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && !e.file_name().to_str().map(|n| n.starts_with('.')).unwrap_or(false)
        })
        .map(|e| e.into_path())
        .collect();
    let mut file_metas = Vec::new();
    for file_path in &files {
        let relative = file_path.strip_prefix(folder).map_err(|e| format!("Path error: {}", e))?;
        let original_name = file_path.file_name().and_then(|n| n.to_str()).ok_or("Invalid filename")?.to_string();
        let locked_name = format!("{}{}", original_name, LOCKED_EXT);
        let plaintext = fs::read(file_path).map_err(|e| format!("Failed to read '{}': {}", file_path.display(), e))?;
        let encrypted = crypto::encrypt(&key, &plaintext)?;
        let locked_path = file_path.with_file_name(&locked_name);
        fs::write(&locked_path, &encrypted).map_err(|e| format!("Failed to write '{}': {}", locked_path.display(), e))?;
        fs::remove_file(file_path).map_err(|e| format!("Failed to remove original '{}': {}", file_path.display(), e))?;
        file_metas.push(FileMeta { original_name, locked_name, relative_path: relative.to_string_lossy().to_string() });
    }
    let has_recovery = recovery_key.is_some();
    let meta = FolderMeta { salt: salt.to_vec(), verify_token, files: file_metas.clone(), recovery_key };
    let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| format!("Metadata serialization error: {}", e))?;
    fs::write(&meta_path, &meta_json).map_err(|e| format!("Failed to write metadata: {}", e))?;
    Ok(ProtectedFolder { path: folder_path.to_string(), is_locked: true, file_count: file_metas.len(), has_recovery })
}

fn decrypt_files(folder: &Path, key: &[u8; 32], files: &[FileMeta]) -> Result<(), String> {
    for file_meta in files {
        let locked_path = folder.join(&file_meta.relative_path).with_file_name(&file_meta.locked_name);
        if !locked_path.exists() { continue; }
        let encrypted = fs::read(&locked_path).map_err(|e| format!("Failed to read '{}': {}", locked_path.display(), e))?;
        let plaintext = crypto::decrypt(key, &encrypted)?;
        let original_path = locked_path.with_file_name(&file_meta.original_name);
        fs::write(&original_path, &plaintext).map_err(|e| format!("Failed to write '{}': {}", original_path.display(), e))?;
        fs::remove_file(&locked_path).map_err(|e| format!("Failed to remove '{}': {}", locked_path.display(), e))?;
    }
    Ok(())
}

fn read_meta(folder_path: &str) -> Result<(FolderMeta, PathBuf), String> {
    let folder = Path::new(folder_path);
    let meta_path = folder.join(META_FILE);
    if !meta_path.exists() {
        return Err("Folder is not locked (no .securelock metadata found)".into());
    }
    let meta_json = fs::read_to_string(&meta_path).map_err(|e| format!("Failed to read metadata: {}", e))?;
    let meta: FolderMeta = serde_json::from_str(&meta_json).map_err(|e| format!("Invalid metadata: {}", e))?;
    Ok((meta, meta_path))
}

pub fn unlock_folder(folder_path: &str, password: &str) -> Result<ProtectedFolder, String> {
    let (meta, meta_path) = read_meta(folder_path)?;
    let folder = Path::new(folder_path);
    let salt: [u8; 32] = meta.salt.clone().try_into().map_err(|_| "Invalid salt in metadata")?;
    let key = crypto::derive_key(password, &salt)?;
    if !crypto::verify_password(&key, &meta.verify_token) {
        return Err("Incorrect password".into());
    }
    let file_count = meta.files.len();
    decrypt_files(folder, &key, &meta.files)?;
    fs::remove_file(&meta_path).map_err(|e| format!("Failed to remove metadata: {}", e))?;
    Ok(ProtectedFolder { path: folder_path.to_string(), is_locked: false, file_count, has_recovery: false })
}

pub fn unlock_folder_with_master_key(folder_path: &str, master_key: &[u8; 32]) -> Result<ProtectedFolder, String> {
    let (meta, meta_path) = read_meta(folder_path)?;
    let folder = Path::new(folder_path);
    let wrapped = meta.recovery_key.ok_or("No recovery key found for this folder")?;
    let folder_key = crypto::unwrap_key(master_key, &wrapped)?;
    if !crypto::verify_password(&folder_key, &meta.verify_token) {
        return Err("Master password verification failed".into());
    }
    let file_count = meta.files.len();
    decrypt_files(folder, &folder_key, &meta.files)?;
    fs::remove_file(&meta_path).map_err(|e| format!("Failed to remove metadata: {}", e))?;
    Ok(ProtectedFolder { path: folder_path.to_string(), is_locked: false, file_count, has_recovery: false })
}

pub fn has_recovery_key(folder_path: &str) -> bool {
    if let Ok((meta, _)) = read_meta(folder_path) {
        return meta.recovery_key.is_some();
    }
    false
}

pub fn is_locked(folder_path: &str) -> bool {
    Path::new(folder_path).join(META_FILE).exists()
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

pub fn count_files(folder_path: &str) -> usize {
    WalkDir::new(folder_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && !e.file_name().to_str().map(|n| n.starts_with('.')).unwrap_or(false)
        })
        .count()
}
