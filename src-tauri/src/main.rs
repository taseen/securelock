#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod commands;
mod crypto;
mod folder;

use commands::AppState;
use tauri::{
    CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem,
};

fn main() {
    let tray_menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("show".to_string(), "Show SecureLock"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("lock_all".to_string(), "Lock All Folders"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit".to_string(), "Quit"));

    let system_tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => {
                if let Some(window) = app.get_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "show" => {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "lock_all" => {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.emit("tray-lock-all", ());
                    }
                }
                "quit" => {
                    std::process::exit(0);
                }
                _ => {}
            },
            _ => {}
        })
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                event.window().hide().unwrap();
                api.prevent_close();
            }
        })
        .setup(|app| {
            let config_dir = app
                .path_resolver()
                .app_config_dir()
                .expect("Failed to get config dir");
            std::fs::create_dir_all(&config_dir).ok();
            let config_path = config_dir.join("config.json").to_string_lossy().to_string();
            app.manage(AppState::new(config_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_folders,
            commands::add_folder,
            commands::remove_folder,
            commands::lock_folder,
            commands::unlock_folder,
            commands::lock_all,
            commands::setup_master_password,
            commands::verify_master_password,
            commands::has_master_password,
            commands::is_master_unlocked,
            commands::check_recovery_key,
            commands::recover_folder,
        ])
        .run(tauri::generate_context!())
        .expect("Error running SecureLock");
}
