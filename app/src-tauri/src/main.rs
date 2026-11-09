//! Bilby desktop app: a Tauri v2 window over Rust-rendered HTML screens.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![commands::render_home])
        .run(tauri::generate_context!())
        .expect("Bilby couldn't start its window");
}
