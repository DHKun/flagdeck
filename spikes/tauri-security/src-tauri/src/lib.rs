#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use tauri::webview::{NewWindowResponse, WebviewWindowBuilder};
use tauri::{Manager, State, Url, WebviewUrl};

const MAX_PING_INPUT: usize = 128;
const FIXTURE_NAME: &str = "safe.txt";
const FIXTURE_CONTENT: &str = "temporary fixture";

struct FixtureState {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

fn ping_value(input: &str) -> Result<String, String> {
    if input.len() > MAX_PING_INPUT {
        return Err("input exceeds 128 bytes".to_owned());
    }
    Ok(format!("pong:{input}"))
}

fn read_fixture_value(name: &str, path: &Path) -> Result<String, String> {
    if name != FIXTURE_NAME {
        return Err("fixture selector rejected".to_owned());
    }
    std::fs::read_to_string(path).map_err(|_| "fixture read failed".to_owned())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn ping(input: String) -> Result<String, String> {
    ping_value(&input)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn read_fixture(name: String, state: State<'_, FixtureState>) -> Result<String, String> {
    read_fixture_value(&name, &state.path)
}

fn allow_navigation(url: &Url) -> bool {
    url.scheme() == "tauri"
        || (cfg!(debug_assertions)
            && url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port() == Some(14_200))
}

fn create_fixture_state() -> Result<FixtureState, Box<dyn std::error::Error>> {
    let directory = tempfile::Builder::new()
        .prefix("flagdeck-tauri-r0-")
        .tempdir()?;
    let path = directory.path().join(FIXTURE_NAME);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(FIXTURE_CONTENT.as_bytes())?;
    file.sync_all()?;
    Ok(FixtureState {
        _directory: directory,
        path,
    })
}

fn create_windows(app: &tauri::App) -> tauri::Result<()> {
    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("FlagDeck Tauri Security Spike")
        .inner_size(900.0, 760.0)
        .devtools(false)
        .on_navigation(allow_navigation)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()?;

    WebviewWindowBuilder::new(app, "untrusted-probe", WebviewUrl::App("probe.html".into()))
        .title("FlagDeck Unprivileged Probe")
        .inner_size(520.0, 260.0)
        .focused(false)
        .devtools(false)
        .on_navigation(allow_navigation)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()?;
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(create_fixture_state()?);
            create_windows(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![ping, read_fixture])
        .run(tauri::generate_context!())
        .expect("Tauri security spike runtime failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_input_limits_are_enforced() {
        assert_eq!(ping_value("ok"), Ok("pong:ok".to_owned()));
        assert!(ping_value(&"x".repeat(MAX_PING_INPUT + 1)).is_err());
    }

    #[test]
    fn file_command_accepts_only_the_fixed_selector() {
        let state = create_fixture_state().expect("fixture state");
        assert_eq!(
            read_fixture_value(FIXTURE_NAME, &state.path),
            Ok(FIXTURE_CONTENT.to_owned())
        );
        assert!(read_fixture_value("../safe.txt", &state.path).is_err());
        assert!(read_fixture_value("/etc/passwd", &state.path).is_err());
    }

    #[test]
    fn navigation_policy_accepts_only_packaged_assets() {
        assert!(allow_navigation(
            &Url::parse("tauri://localhost/index.html").expect("local URL")
        ));
        assert!(!allow_navigation(
            &Url::parse("https://example.invalid/").expect("remote URL")
        ));
        assert!(!allow_navigation(
            &Url::parse("file:///etc/passwd").expect("file URL")
        ));
    }
}
