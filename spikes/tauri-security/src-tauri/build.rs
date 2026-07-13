fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["ping", "read_fixture"])),
    )
    .expect("failed to build Tauri security spike manifest");
}
