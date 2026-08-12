//! Subprocess-based browser login to Roblox using Ungoogled Chromium.
//!
//! Spawns a genuine Ungoogled Chromium browser process with Chrome DevTools Protocol (CDP)
//! enabled via `--remote-debugging-port`. Captures `.ROBLOSECURITY` session cookies via WebSocket
//! CDP commands on the Browser Target (`Storage.getCookies`) and profile disk scanning.
//!
//! If no Ungoogled Chromium binary is present on the system, auto-downloads the latest
//! release build from `ungoogled-software/ungoogled-chromium-portablelinux` into the app data directory.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tracing::{info, warn};
use tungstenite::connect;

/// CLI flag that switches `main()` into child browser login mode.
/// Invoked as: `ram_ui --browser-login <profile_dir> <outfile> [statusfile]`.
pub const FLAG: &str = "--browser-login";

/// CLI flag for the "Open browser as <account>" child mode.
/// Invoked as: `ram_ui --browse-as <profile_dir> <cookie_file> <label>`.
pub const BROWSE_AS_FLAG: &str = "--browse-as";

const LOGIN_URL: &str = "https://www.roblox.com/login";
const BROWSE_AS_HOME_URL: &str = "https://www.roblox.com/home";
const POLL_INTERVAL: Duration = Duration::from_millis(50);

pub enum LoginOutcome {
    Status(String),
    Success(String),
    Cancelled,
    Failed(String),
}

// ---------------------------------------------------------------------------
// Parent side — spawn the helper subprocess and deliver its result.
// ---------------------------------------------------------------------------

pub fn spawn(profile_dir: PathBuf, tx: Sender<LoginOutcome>) {
    std::thread::spawn(move || {
        let outcome = match spawn_and_wait(profile_dir, &tx) {
            Ok(o) => o,
            Err(e) => {
                warn!("browser_login parent: {e}");
                LoginOutcome::Failed(e)
            }
        };
        let _ = tx.send(outcome);
    });
}

fn spawn_and_wait(profile_dir: PathBuf, tx: &Sender<LoginOutcome>) -> Result<LoginOutcome, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let outfile = profile_dir.join("cookie.out");
    let status_file = profile_dir.join("status.out");

    // Clear any leftover from a prior attempt so `exists()` means "this run"
    let _ = std::fs::remove_file(&outfile);
    let _ = std::fs::remove_file(&status_file);

    info!("browser_login parent: spawning child {}", exe.display());
    let mut child = std::process::Command::new(&exe)
        .arg(FLAG)
        .arg(&profile_dir)
        .arg(&outfile)
        .arg(&status_file)
        .spawn()
        .map_err(|e| format!("spawn child: {e}"))?;

    let mut last_status = String::new();

    while child.try_wait().map_err(|e| format!("try_wait: {e}"))?.is_none() {
        if let Ok(st) = std::fs::read_to_string(&status_file) {
            let st_trimmed = st.trim();
            if !st_trimmed.is_empty() && st_trimmed != last_status {
                last_status = st_trimmed.to_string();
                let _ = tx.send(LoginOutcome::Status(last_status.clone()));
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }

    match std::fs::read_to_string(&outfile) {
        Ok(cookie) if !cookie.trim().is_empty() => {
            let cookie = cookie.trim().to_string();
            let _ = std::fs::remove_file(&outfile);
            let _ = std::fs::remove_file(&status_file);
            Ok(LoginOutcome::Success(cookie))
        }
        _ => {
            let _ = std::fs::remove_file(&status_file);
            Ok(LoginOutcome::Cancelled)
        }
    }
}

// ---------------------------------------------------------------------------
// Helper — status file writer & Chromium launcher
// ---------------------------------------------------------------------------

fn write_status(status_file: Option<&Path>, msg: &str) {
    if let Some(sf) = status_file {
        let _ = std::fs::write(sf, msg);
    }
}

fn spawn_chromium_cmd(
    chromium_bin: &Path,
    profile_dir: &Path,
    port: u16,
    target_url: &str,
) -> Result<std::process::Child, String> {
    let mut cmd = std::process::Command::new(chromium_bin);
    let bin_str = chromium_bin.to_string_lossy().to_lowercase();
    if bin_str.contains("appimage") {
        cmd.arg("--appimage-extract-and-run");
    }
    cmd.arg(format!("--remote-debugging-port={port}"))
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--password-store=basic")
        .arg(target_url);

    cmd.spawn()
        .map_err(|e| format!("failed to spawn ungoogled-chromium process: {e}"))
}

/// Fallback disk scanner for Chromium SQLite Cookies & Cookies-wal files
fn check_disk_cookie(profile_dir: &Path) -> Option<String> {
    let candidates = [
        profile_dir.join("Default").join("Network").join("Cookies"),
        profile_dir.join("Default").join("Network").join("Cookies-wal"),
        profile_dir.join("Network").join("Cookies"),
        profile_dir.join("Network").join("Cookies-wal"),
        profile_dir.join("Default").join("Cookies"),
        profile_dir.join("Default").join("Cookies-wal"),
        profile_dir.join("Cookies"),
        profile_dir.join("Cookies-wal"),
    ];
    for cookie_file in candidates {
        if !cookie_file.exists() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&cookie_file) else {
            continue;
        };
        let content = String::from_utf8_lossy(&bytes);
        if let Some(pos) = content.find("_|WARNING:-DO-NOT-SHARE-THIS!") {
            let rest = &content[pos..];
            let end = rest
                .find(|c: char| c.is_ascii_whitespace() || c == ';' || c == '"' || c == '\'' || c == '\\' || c == '\0')
                .unwrap_or(rest.len());
            let cookie = rest[..end].trim().to_string();
            if cookie.len() > 50 {
                return Some(cookie);
            }
        }
    }
    None
}

/// Extracts .ROBLOSECURITY token string from raw text (e.g. WebSocket frame or JSON)
fn extract_cookie_from_text(text: &str) -> Option<String> {
    if let Some(pos) = text.find("_|WARNING:-DO-NOT-SHARE-THIS!") {
        let rest = &text[pos..];
        let end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == ';' || c == '"' || c == '\'' || c == '\\' || c == '\0')
            .unwrap_or(rest.len());
        let cookie = rest[..end].trim().to_string();
        if cookie.len() > 50 {
            return Some(cookie);
        }
    }
    None
}

fn close_chromium(port: u16, child: &mut std::process::Child) {
    info!("Closing Ungoogled Chromium session on port {port}");

    let version_url = format!("http://127.0.0.1:{port}/json/version");
    if let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    {
        if let Ok(resp) = client.get(&version_url).send() {
            if let Ok(json) = resp.json::<Value>() {
                if let Some(ws_url) = json["webSocketDebuggerUrl"].as_str() {
                    if let Ok((mut socket, _)) = connect(ws_url) {
                        let close_req = json!({
                            "id": 9999,
                            "method": "Browser.close",
                            "params": {}
                        });
                        let _ = socket.send(tungstenite::Message::Text(close_req.to_string().into()));
                    }
                }
            }
        }
    }

    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(1000) {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Child side — runs Ungoogled Chromium, queries CDP for auth cookie, exits.
// ---------------------------------------------------------------------------

/// Entry point for the child login process.
pub fn run_child(profile_dir: PathBuf, outfile: PathBuf, status_file: Option<PathBuf>) -> i32 {
    match run_child_inner(profile_dir, outfile, status_file.as_deref()) {
        Ok(()) => 0,
        Err(e) => {
            warn!("browser_login child: {e}");
            1
        }
    }
}

fn run_child_inner(
    profile_dir: PathBuf,
    outfile: PathBuf,
    status_file: Option<&Path>,
) -> Result<(), String> {
    info!(
        "browser_login child: start, profile={}, out={}",
        profile_dir.display(),
        outfile.display()
    );
    std::fs::create_dir_all(&profile_dir).map_err(|e| format!("create profile dir: {e}"))?;

    let chromium_bin = find_or_download_chromium(status_file)?;
    let port = get_free_port();

    info!(
        "Spawning Ungoogled Chromium ({}) on remote debugging port {}",
        chromium_bin.display(),
        port
    );

    write_status(status_file, "Starting Ungoogled Chromium...");
    let mut child = spawn_chromium_cmd(&chromium_bin, &profile_dir, port, LOGIN_URL)?;

    write_status(status_file, "Connecting to browser CDP...");
    let ws_url = get_cdp_ws_url(port)?;
    info!("Connected to CDP browser target: {ws_url}");

    let (mut socket, _) =
        connect(ws_url.as_str()).map_err(|e| format!("websocket connect: {e}"))?;

    if let tungstenite::stream::MaybeTlsStream::Plain(ref s) = socket.get_ref() {
        let _ = s.set_read_timeout(Some(Duration::from_millis(5)));
    }

    // Enable Target auto-attach across all browser contexts
    let auto_attach = json!({
        "id": 1,
        "method": "Target.setAutoAttach",
        "params": {
            "autoAttach": true,
            "waitForDebuggerOnStart": false,
            "flatten": true
        }
    });
    let _ = socket.send(tungstenite::Message::Text(auto_attach.to_string().into()));

    write_status(status_file, "Sign in to Roblox in Ungoogled Chromium.");

    let mut msg_id = 2;
    let start = Instant::now();
    let timeout = Duration::from_secs(600);

    while start.elapsed() < timeout {
        if let Ok(Some(status)) = child.try_wait() {
            info!("Ungoogled Chromium exited with status: {status}");
            if let Some(cookie) = check_disk_cookie(&profile_dir) {
                info!("Captured .ROBLOSECURITY cookie from profile disk after browser exit!");
                let _ = std::fs::write(&outfile, &cookie);
                return Ok(());
            }
            break;
        }

        // 1. Instant check on disk cookies (SQLite + WAL)
        if let Some(cookie) = check_disk_cookie(&profile_dir) {
            info!("Captured .ROBLOSECURITY cookie from profile disk!");
            let _ = std::fs::write(&outfile, &cookie);
            close_chromium(port, &mut child);
            return Ok(());
        }

        // 2. Query Storage.getCookies on Browser Target (returns all profile cookies)
        let req_storage = json!({
            "id": msg_id,
            "method": "Storage.getCookies",
            "params": {}
        });
        msg_id += 1;

        let _ = socket.send(tungstenite::Message::Text(req_storage.to_string().into()));

        // 3. Process all incoming WebSocket frames continuously
        while let Ok(msg) = socket.read() {
            if let tungstenite::Message::Text(msg_text) = msg {
                let text_str = msg_text.as_str();

                // Direct text extraction scan (matches Set-Cookie header events, JSON, and network frames)
                if let Some(cookie) = extract_cookie_from_text(text_str) {
                    info!("Captured .ROBLOSECURITY cookie instantly from Browser CDP stream!");
                    let _ = std::fs::write(&outfile, &cookie);
                    close_chromium(port, &mut child);
                    return Ok(());
                }

                // Structured JSON scan
                if let Ok(parsed) = serde_json::from_str::<Value>(text_str) {
                    if let Some(cookies) = parsed["result"]["cookies"].as_array() {
                        for cookie in cookies {
                            if cookie["name"].as_str() == Some(".ROBLOSECURITY") {
                                if let Some(val) = cookie["value"].as_str() {
                                    let trimmed = val.trim();
                                    if !trimmed.is_empty() {
                                        info!("Captured .ROBLOSECURITY cookie from Browser CDP JSON!");
                                        let _ = std::fs::write(&outfile, trimmed);
                                        close_chromium(port, &mut child);
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                    if parsed.get("id").is_some() {
                        break;
                    }
                }
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    }

    close_chromium(port, &mut child);
    Ok(())
}

// ---------------------------------------------------------------------------
// "Open browser as" — spawn Ungoogled Chromium pre-authenticated via CDP
// ---------------------------------------------------------------------------

pub fn spawn_browse_as(profile_dir: PathBuf, cookie: String, label: String) -> Result<(), String> {
    std::fs::create_dir_all(&profile_dir).map_err(|e| format!("create profile dir: {e}"))?;
    let cookie_in = profile_dir.join("cookie.in");
    let _ = std::fs::remove_file(&cookie_in);
    std::fs::write(&cookie_in, cookie.as_bytes())
        .map_err(|e| format!("write cookie file: {e}"))?;

    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    info!("browse_as parent: spawning child {}", exe.display());
    std::process::Command::new(&exe)
        .arg(BROWSE_AS_FLAG)
        .arg(&profile_dir)
        .arg(&cookie_in)
        .arg(&label)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            let _ = std::fs::remove_file(&cookie_in);
            format!("spawn child: {e}")
        })?;
    Ok(())
}

pub fn run_browse_as_child(profile_dir: PathBuf, cookie_in: PathBuf, label: String) -> i32 {
    match run_browse_as_inner(profile_dir, cookie_in, label) {
        Ok(()) => 0,
        Err(e) => {
            warn!("browse_as child: {e}");
            1
        }
    }
}

fn run_browse_as_inner(
    profile_dir: PathBuf,
    cookie_in: PathBuf,
    label: String,
) -> Result<(), String> {
    info!("browse_as child: start, profile={}", profile_dir.display());

    let cookie_value =
        std::fs::read_to_string(&cookie_in).map_err(|e| format!("read cookie file: {e}"))?;
    let _ = std::fs::remove_file(&cookie_in);
    let cookie_value = cookie_value.trim().to_string();
    if cookie_value.is_empty() {
        return Err("empty cookie hand-off".into());
    }

    std::fs::create_dir_all(&profile_dir).map_err(|e| format!("create profile dir: {e}"))?;

    let chromium_bin = find_or_download_chromium(None)?;
    let port = get_free_port();

    let mut child = spawn_chromium_cmd(&chromium_bin, &profile_dir, port, "about:blank")?;

    let ws_url = get_cdp_page_ws_url(port)?;
    let (mut socket, _) =
        connect(ws_url.as_str()).map_err(|e| format!("websocket connect: {e}"))?;

    if let tungstenite::stream::MaybeTlsStream::Plain(ref s) = socket.get_ref() {
        let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    }

    let enable_req = json!({
        "id": 1,
        "method": "Network.enable",
        "params": {}
    });
    let _ = socket.send(tungstenite::Message::Text(enable_req.to_string().into()));

    let set_cookie_req = json!({
        "id": 2,
        "method": "Network.setCookie",
        "params": {
            "name": ".ROBLOSECURITY",
            "value": cookie_value,
            "domain": ".roblox.com",
            "path": "/",
            "secure": true,
            "httpOnly": true
        }
    });
    let _ = socket.send(tungstenite::Message::Text(set_cookie_req.to_string().into()));

    // Wait for Network.setCookie response to guarantee cookie is registered before navigation
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(msg) = socket.read() {
            if let tungstenite::Message::Text(msg_text) = msg {
                if let Ok(parsed) = serde_json::from_str::<Value>(msg_text.as_str()) {
                    if parsed.get("id").and_then(|v| v.as_i64()) == Some(2) {
                        info!("Network.setCookie acknowledged by CDP target");
                        break;
                    }
                }
            }
        }
    }

    let nav_req = json!({
        "id": 3,
        "method": "Page.navigate",
        "params": {
            "url": BROWSE_AS_HOME_URL
        }
    });
    let _ = socket.send(tungstenite::Message::Text(nav_req.to_string().into()));

    // Wait for Page.navigate response
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(msg) = socket.read() {
            if let tungstenite::Message::Text(msg_text) = msg {
                if let Ok(parsed) = serde_json::from_str::<Value>(msg_text.as_str()) {
                    if parsed.get("id").and_then(|v| v.as_i64()) == Some(3) {
                        info!("Page.navigate acknowledged by CDP target");
                        break;
                    }
                }
            }
        }
    }

    info!("Ungoogled Chromium launched as '{label}'. Waiting for exit...");
    let _ = child.wait();
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers — locate/download Ungoogled Chromium binary & query CDP port
// ---------------------------------------------------------------------------

pub fn find_or_download_chromium(status_file: Option<&Path>) -> Result<PathBuf, String> {
    write_status(status_file, "Locating Ungoogled Chromium installation...");
    if let Ok(env_path) = std::env::var("UNGOOGLED_CHROMIUM_PATH") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Ok(p);
        }
    }
    if let Ok(env_path) = std::env::var("CHROMIUM_PATH") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Ok(p);
        }
    }

    let data_chrom_dir = crate::data_dir().join("chromium");
    let appimage_path = data_chrom_dir.join("ungoogled-chromium.AppImage");
    if appimage_path.exists() {
        return Ok(appimage_path);
    }
    let extracted_binary = data_chrom_dir.join("chrome-linux").join("chrome");
    if extracted_binary.exists() {
        return Ok(extracted_binary);
    }

    let system_candidates = [
        "ungoogled-chromium",
        "chromium-browser",
        "chromium",
        "google-chrome",
    ];

    for candidate in &system_candidates {
        for prefix in &[
            "/usr/bin",
            "/usr/local/bin",
            "/var/lib/flatpak/exports/bin",
            "/snap/bin",
        ] {
            let sys_path = Path::new(prefix).join(candidate);
            if sys_path.exists() {
                return Ok(sys_path);
            }
        }
    }

    info!("Ungoogled Chromium not found on system. Downloading latest release build...");
    download_ungoogled_chromium(&appimage_path, status_file)?;
    Ok(appimage_path)
}

fn download_ungoogled_chromium(target_path: &Path, status_file: Option<&Path>) -> Result<(), String> {
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create chromium dir: {e}"))?;
    }

    write_status(status_file, "Checking GitHub for latest Ungoogled Chromium release...");

    let client = reqwest::blocking::Client::builder()
        .user_agent("RM4Linux/1.9 (UngoogledChromiumDownloader)")
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| format!("http client build failed: {e}"))?;

    let api_url =
        "https://api.github.com/repos/ungoogled-software/ungoogled-chromium-portablelinux/releases/latest";
    let resp = client
        .get(api_url)
        .send()
        .map_err(|e| format!("failed to query GitHub API: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned HTTP {}", resp.status()));
    }

    let release_info: Value = resp
        .json()
        .map_err(|e| format!("failed to parse GitHub release JSON: {e}"))?;

    let assets = release_info["assets"]
        .as_array()
        .ok_or_else(|| "No assets found in GitHub release".to_string())?;

    let asset = assets
        .iter()
        .find(|a| {
            let name = a["name"].as_str().unwrap_or_default();
            name.contains("x86_64") && name.ends_with(".AppImage")
        })
        .ok_or_else(|| "No x86_64 AppImage asset found in release".to_string())?;

    let download_url = asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| "Missing download URL for asset".to_string())?;

    info!(
        "Downloading Ungoogled Chromium AppImage from {download_url} to {}",
        target_path.display()
    );

    write_status(status_file, "Downloading Ungoogled Chromium AppImage...");

    let mut download_resp = client
        .get(download_url)
        .send()
        .map_err(|e| format!("failed to download ungoogled-chromium AppImage: {e}"))?;

    if !download_resp.status().is_success() {
        return Err(format!("Download returned HTTP {}", download_resp.status()));
    }

    let total_bytes = download_resp.content_length().unwrap_or(0);
    let temp_path = target_path.with_extension("tmp");
    let mut file = std::fs::File::create(&temp_path)
        .map_err(|e| format!("failed to create temp file: {e}"))?;

    use std::io::{Read, Write};
    let mut downloaded_bytes: u64 = 0;
    let mut buffer = [0u8; 65536];
    let mut last_update = Instant::now();

    loop {
        let n = download_resp.read(&mut buffer).map_err(|e| format!("download read error: {e}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buffer[..n]).map_err(|e| format!("write error: {e}"))?;
        downloaded_bytes += n as u64;

        if last_update.elapsed() >= Duration::from_millis(250) {
            last_update = Instant::now();
            let msg = if total_bytes > 0 {
                let d_mb = downloaded_bytes as f64 / 1_048_576.0;
                let t_mb = total_bytes as f64 / 1_048_576.0;
                let pct = (downloaded_bytes as f64 / total_bytes as f64 * 100.0) as u32;
                format!("Downloading Ungoogled Chromium... ({d_mb:.1} MB / {t_mb:.1} MB - {pct}%)")
            } else {
                let d_mb = downloaded_bytes as f64 / 1_048_576.0;
                format!("Downloading Ungoogled Chromium... ({d_mb:.1} MB)")
            };
            write_status(status_file, &msg);
        }
    }

    write_status(status_file, "Preparing Ungoogled Chromium executable...");

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&temp_path).unwrap().permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&temp_path, perms);
    }

    std::fs::rename(&temp_path, target_path)
        .map_err(|e| format!("failed to save downloaded AppImage: {e}"))?;

    info!(
        "Successfully downloaded Ungoogled Chromium to {}",
        target_path.display()
    );
    Ok(())
}

fn get_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(9222)
}

fn get_cdp_ws_url(port: u16) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .map_err(|e| e.to_string())?;

    let version_url = format!("http://127.0.0.1:{port}/json/version");
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(15) {
        if let Ok(resp) = client.get(&version_url).send() {
            if let Ok(json) = resp.json::<Value>() {
                if let Some(ws) = json["webSocketDebuggerUrl"].as_str() {
                    return Ok(ws.to_string());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    Err(format!("Timed out waiting for CDP endpoint at {version_url}"))
}

fn get_cdp_page_ws_url(port: u16) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .map_err(|e| e.to_string())?;

    let list_url = format!("http://127.0.0.1:{port}/json/list");
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(15) {
        if let Ok(resp) = client.get(&list_url).send() {
            if let Ok(targets) = resp.json::<Value>() {
                if let Some(arr) = targets.as_array() {
                    for target in arr {
                        if target["type"].as_str() == Some("page") {
                            if let Some(ws) = target["webSocketDebuggerUrl"].as_str() {
                                return Ok(ws.to_string());
                            }
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    Err(format!("Timed out waiting for page CDP endpoint at {list_url}"))
}
