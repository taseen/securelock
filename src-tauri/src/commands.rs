use crate::crypto;
use crate::folder::{self, ProtectedFolder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tauri::State;
use zeroize::Zeroizing;

pub(crate) struct CachedCredentials {
    password: Zeroizing<String>,
    hint: Option<String>,
    use_master: bool,
}

pub struct AppState {
    pub folders: Mutex<Vec<String>>,
    pub master_salt: Mutex<Option<Vec<u8>>>,
    pub master_verify_token: Mutex<Option<Vec<u8>>>,
    pub master_key: Mutex<Option<[u8; 32]>>,
    pub config_path: String,
    pub relock_cache: Mutex<HashMap<String, CachedCredentials>>,
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
            relock_cache: Mutex::new(HashMap::new()),
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
    let relock_cache = state.relock_cache.lock().unwrap();
    folders
        .iter()
        .map(|path| {
            let is_locked = folder::is_locked(path);
            let file_count = folder::get_file_count(path);
            let has_recovery = if is_locked {
                folder::has_recovery_key(path)
            } else {
                false
            };
            let hint = folder::get_hint_for_folder(path);
            let has_relock = !is_locked && relock_cache.contains_key(path);
            ProtectedFolder {
                path: path.clone(),
                is_locked,
                file_count,
                has_recovery,
                hint,
                has_relock,
            }
        })
        .collect()
}

#[tauri::command]
pub fn add_folder(path: String, state: State<'_, AppState>) -> Result<ProtectedFolder, String> {
    let mut folders = state.folders.lock().unwrap();
    if folders.contains(&path) {
        return Err("Folder is already in the list".into());
    }

    let p = Path::new(&path);
    let is_dir = p.is_dir();
    let is_vault = path.ends_with(".vault") && p.is_file();
    if !is_dir && !is_vault {
        return Err("Path must be a folder or a .vault file".into());
    }

    folders.push(path.clone());
    drop(folders);
    state.save();

    let is_locked = folder::is_locked(&path);
    let file_count = folder::get_file_count(&path);
    let has_recovery = if is_locked {
        folder::has_recovery_key(&path)
    } else {
        false
    };
    let hint = folder::get_hint_for_folder(&path);

    Ok(ProtectedFolder {
        path,
        is_locked,
        file_count,
        has_recovery,
        hint,
        has_relock: false,
    })
}

#[tauri::command]
pub fn remove_folder(path: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut folders = state.folders.lock().unwrap();
    folders.retain(|f| f != &path);
    drop(folders);
    state.relock_cache.lock().unwrap().remove(&path);
    state.save();
    Ok(())
}

#[tauri::command]
pub fn lock_folder(
    path: String,
    password: String,
    hint: Option<String>,
    use_master: bool,
    state: State<'_, AppState>,
) -> Result<ProtectedFolder, String> {
    let master_key_opt = if use_master {
        state.master_key.lock().unwrap().clone()
    } else {
        None
    };

    let result = folder::lock_folder(&path, &password, hint, master_key_opt.as_ref())?;

    // Clear relock cache for this folder
    state.relock_cache.lock().unwrap().remove(&path);

    // Update stored path: folder path → vault path
    let mut folders = state.folders.lock().unwrap();
    if let Some(pos) = folders.iter().position(|f| f == &path) {
        folders[pos] = result.path.clone();
    }
    drop(folders);
    state.save();

    Ok(result)
}

#[tauri::command]
pub fn unlock_folder(
    path: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<ProtectedFolder, String> {
    // Read vault metadata before unlock deletes the file
    let vault_meta = folder::get_vault_lock_metadata(&path);

    let result = if folder::is_legacy_locked(&path) {
        folder::unlock_folder_legacy(&path, &password)?
    } else {
        folder::unlock_folder(&path, &password)?
    };

    // Cache credentials for re-lock
    let (hint, use_master) = match vault_meta {
        Some((hint, has_recovery)) => (hint, has_recovery),
        None => (None, false),
    };
    state.relock_cache.lock().unwrap().insert(
        result.path.clone(),
        CachedCredentials {
            password: Zeroizing::new(password),
            hint,
            use_master,
        },
    );

    // Update stored path: vault path → folder path
    let mut folders = state.folders.lock().unwrap();
    if let Some(pos) = folders.iter().position(|f| f == &path) {
        folders[pos] = result.path.clone();
    }
    drop(folders);
    state.save();

    Ok(result)
}

#[tauri::command]
pub fn lock_all(
    password: String,
    hint: Option<String>,
    use_master: bool,
    state: State<'_, AppState>,
) -> Result<Vec<ProtectedFolder>, String> {
    let master_key_opt = if use_master {
        state.master_key.lock().unwrap().clone()
    } else {
        None
    };
    let folders_snapshot = state.folders.lock().unwrap().clone();

    let mut results = Vec::new();
    let mut path_updates: Vec<(String, String)> = Vec::new();

    for path in &folders_snapshot {
        if !folder::is_locked(path) {
            match folder::lock_folder(path, &password, hint.clone(), master_key_opt.as_ref()) {
                Ok(pf) => {
                    path_updates.push((path.clone(), pf.path.clone()));
                    results.push(pf);
                }
                Err(e) => return Err(format!("Failed to lock '{}': {}", path, e)),
            }
        }
    }

    // Clear relock cache for all locked folders
    let mut relock_cache = state.relock_cache.lock().unwrap();
    for (old, _) in &path_updates {
        relock_cache.remove(old);
    }
    drop(relock_cache);

    // Apply all path updates at once
    let mut folders = state.folders.lock().unwrap();
    for (old, new) in path_updates {
        if let Some(pos) = folders.iter().position(|f| f == &old) {
            folders[pos] = new;
        }
    }
    drop(folders);
    state.save();

    Ok(results)
}

#[tauri::command]
pub fn get_vault_hint(path: String) -> Option<String> {
    folder::get_vault_hint(&path)
}

#[tauri::command]
pub fn setup_master_password(
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
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
pub fn verify_master_password(
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let salt_opt = state.master_salt.lock().unwrap().clone();
    let token_opt = state.master_verify_token.lock().unwrap().clone();
    let salt_vec = salt_opt.ok_or("No master password configured")?;
    let token = token_opt.ok_or("No master password configured")?;
    let salt: [u8; 32] = salt_vec
        .try_into()
        .map_err(|_| "Invalid master salt".to_string())?;
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
pub fn recover_folder(
    path: String,
    state: State<'_, AppState>,
) -> Result<ProtectedFolder, String> {
    let master_key = state.master_key.lock().unwrap();
    let key = master_key
        .as_ref()
        .ok_or("Master password not unlocked for this session")?;

    let result = if folder::is_legacy_locked(&path) {
        folder::unlock_folder_legacy_with_master_key(&path, key)?
    } else {
        folder::unlock_folder_with_master_key(&path, key)?
    };
    drop(master_key);

    // Update stored path: vault path → folder path
    let mut folders = state.folders.lock().unwrap();
    if let Some(pos) = folders.iter().position(|f| f == &path) {
        folders[pos] = result.path.clone();
    }
    drop(folders);
    state.save();

    Ok(result)
}

#[tauri::command]
pub fn relock_folder(path: String, state: State<'_, AppState>) -> Result<ProtectedFolder, String> {
    let cached = state
        .relock_cache
        .lock()
        .unwrap()
        .remove(&path)
        .ok_or("No cached credentials for re-lock")?;

    let master_key_opt = if cached.use_master {
        state.master_key.lock().unwrap().clone()
    } else {
        None
    };

    let result = folder::lock_folder(
        &path,
        &cached.password,
        cached.hint,
        master_key_opt.as_ref(),
    )?;

    // Update stored path
    let mut folders = state.folders.lock().unwrap();
    if let Some(pos) = folders.iter().position(|f| f == &path) {
        folders[pos] = result.path.clone();
    }
    drop(folders);
    state.save();

    Ok(result)
}
