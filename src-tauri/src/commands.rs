use crate::crypto;
use crate::folder::{self, ProtectedFolder};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;
use tauri::State;

pub struct AppState {
    pub folders: Mutex<Vec<String>>,
    pub master_salt: Mutex<Option<Vec<u8>>>,
    pub master_verify_token: Mutex<Option<Vec<u8>>>,
    pub master_key: Mutex<Option<[u8; 32]>>,
    pub config_path: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Config {
    folders: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    master_salt: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    master_verify_token: Option<Vec<u8>>,
}

impl AppState {
    pub fn new(config_path: String) -> Self {
        let (folders, master_salt, master_verify_token) =
            if let Ok(data) = fs::read_to_string(&config_path) {
                if let Ok(config) = serde_json::from_str::<Config>(&data) {
                    (config.folders, config.master_salt, config.master_verify_token)
                } else {
                    (Vec::new(), None, None)
                }
            } else {
                (Vec::new(), None, None)
            };
        AppState {
            folders: Mutex::new(folders),
            master_salt: Mutex::new(master_salt),
            master_verify_token: Mutex::new(master_verify_token),
            master_key: Mutex::new(None),
            config_path,
        }
    }

    fn save(&self) {
        let folders = self.folders.lock().unwrap();
        let master_salt = self.master_salt.lock().unwrap();
        let master_verify_token = self.master_verify_token.lock().unwrap();
        let config = Config {
            folders: folders.clone(),
            master_salt: master_salt.clone(),
            master_verify_token: master_verify_token.clone(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&config) {
            let _ = fs::write(&self.config_path, json);
        }
    }
}

#[tauri::command]
pub fn get_folders(state: State<'_, AppState>) -> Vec<ProtectedFolder> {
    let folders = state.folders.lock().unwrap();
    folders.iter().map(|path| {
        let is_locked = folder::is_locked(path);
        let file_count = if is_locked { folder::get_locked_file_count(path) } else { folder::count_files(path) };
        let has_recovery = if is_locked { folder::has_recovery_key(path) } else { false };
        ProtectedFolder { path: path.clone(), is_locked, file_count, has_recovery }
    }).collect()
}

#[tauri::command]
pub fn add_folder(path: String, state: State<'_, AppState>) -> Result<ProtectedFolder, String> {
    let mut folders = state.folders.lock().unwrap();
    if folders.contains(&path) { return Err("Folder is already in the list".into()); }
    if !std::path::Path::new(&path).is_dir() { return Err("Path is not a valid directory".into()); }
    folders.push(path.clone());
    drop(folders);
    state.save();
    let is_locked = folder::is_locked(&path);
    let file_count = if is_locked { folder::get_locked_file_count(&path) } else { folder::count_files(&path) };
    let has_recovery = if is_locked { folder::has_recovery_key(&path) } else { false };
    Ok(ProtectedFolder { path, is_locked, file_count, has_recovery })
}

#[tauri::command]
pub fn remove_folder(path: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut folders = state.folders.lock().unwrap();
    folders.retain(|f| f != &path);
    drop(folders);
    state.save();
    Ok(())
}

#[tauri::command]
pub fn lock_folder(path: String, password: String, state: State<'_, AppState>) -> Result<ProtectedFolder, String> {
    let master_key = state.master_key.lock().unwrap();
    folder::lock_folder(&path, &password, master_key.as_ref())
}

#[tauri::command]
pub fn unlock_folder(path: String, password: String) -> Result<ProtectedFolder, String> {
    folder::unlock_folder(&path, &password)
}

#[tauri::command]
pub fn lock_all(password: String, state: State<'_, AppState>) -> Result<Vec<ProtectedFolder>, String> {
    let master_key = state.master_key.lock().unwrap().clone();
    let folders = state.folders.lock().unwrap();
    let mut results = Vec::new();
    for path in folders.iter() {
        if !folder::is_locked(path) {
            match folder::lock_folder(path, &password, master_key.as_ref()) {
                Ok(pf) => results.push(pf),
                Err(e) => return Err(format!("Failed to lock '{}': {}", path, e)),
            }
        }
    }
    Ok(results)
}

#[tauri::command]
pub fn setup_master_password(password: String, state: State<'_, AppState>) -> Result<(), String> {
    if password.len() < 4 {
        return Err("Master password must be at least 4 characters".into());
    }
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(&password, &salt)?;
    let verify_token = crypto::create_verify_token(&key)?;
    *state.master_salt.lock().unwrap() = Some(salt.to_vec());
    *state.master_verify_token.lock().unwrap() = Some(verify_token);
    *state.master_key.lock().unwrap() = Some(key);
    state.save();
    Ok(())
}

#[tauri::command]
pub fn verify_master_password(password: String, state: State<'_, AppState>) -> Result<(), String> {
    let salt_opt = state.master_salt.lock().unwrap().clone();
    let token_opt = state.master_verify_token.lock().unwrap().clone();
    let salt_vec = salt_opt.ok_or("No master password configured")?;
    let token = token_opt.ok_or("No master password configured")?;
    let salt: [u8; 32] = salt_vec.try_into().map_err(|_| "Invalid master salt")?;
    let key = crypto::derive_key(&password, &salt)?;
    if !crypto::verify_password(&key, &token) {
        return Err("Incorrect master password".into());
    }
    *state.master_key.lock().unwrap() = Some(key);
    Ok(())
}

#[tauri::command]
pub fn has_master_password(state: State<'_, AppState>) -> bool {
    state.master_salt.lock().unwrap().is_some()
}

#[tauri::command]
pub fn is_master_unlocked(state: State<'_, AppState>) -> bool {
    state.master_key.lock().unwrap().is_some()
}

#[tauri::command]
pub fn check_recovery_key(path: String) -> bool {
    folder::has_recovery_key(&path)
}

#[tauri::command]
pub fn recover_folder(path: String, state: State<'_, AppState>) -> Result<ProtectedFolder, String> {
    let master_key = state.master_key.lock().unwrap();
    let key = master_key.as_ref().ok_or("Master password not unlocked for this session")?;
    folder::unlock_folder_with_master_key(&path, key)
}
