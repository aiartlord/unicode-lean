//! Integration tests for the `unicode-security` binary.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_unicode-security")
}

fn temp_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "unicode-security-cli-{}-{name}",
        std::process::id()
    ));
    fs::write(&path, bytes).expect("write temp fixture");
    path
}

fn fixture(name: &str) -> String {
    fs::read_to_string(format!("fixtures/security/cli/{name}")).expect("read cli fixture")
}

fn scan_file_json(
    name: &str,
    encoding: Option<&str>,
    profile: &str,
    mode: &str,
    bytes: &[u8],
) -> Output {
    let path = temp_file(name, bytes);
    let mut command = Command::new(bin());
    command.args([
        "scan",
        "--profile",
        profile,
        "--mode",
        mode,
        "--input",
        path.to_str().expect("utf-8 path"),
        "--json",
    ]);
    if let Some(encoding) = encoding {
        command.args(["--encoding", encoding]);
    }
    let output = command.output().expect("run unicode-security");
    let _ = fs::remove_file(path);
    output
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout utf-8")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr utf-8")
}

fn run_jsonl_input(input: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(["scan", "--jsonl"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn unicode-security");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");

    child.wait_with_output().expect("wait unicode-security")
}

fn run_stdio_jsonl_server(input: &[u8], extra_args: &[&str]) -> Output {
    let mut child = Command::new(bin())
        .args(["serve", "--stdio-jsonl"])
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn unicode-security stdio-jsonl server");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write stdio-jsonl frame");

    child.wait_with_output().expect("wait stdio-jsonl server")
}

fn assert_stdout_contains(output: &Output, needle: &str) {
    let stdout = stdout_text(output);
    assert!(
        stdout.contains(needle),
        "stdout missing {needle:?}\nstdout={stdout}"
    );
}

struct ServeProcess {
    child: Child,
    addr: String,
    _server_lock: MutexGuard<'static, ()>,
}

#[cfg(unix)]
struct UnixServeProcess {
    child: Child,
    path: std::path::PathBuf,
    _server_lock: MutexGuard<'static, ()>,
}

impl Drop for ServeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
impl Drop for UnixServeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

impl ServeProcess {
    fn stop_and_stderr(mut self) -> String {
        let mut stderr = self.child.stderr.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut text = String::new();
        if let Some(stderr) = stderr.as_mut() {
            stderr.read_to_string(&mut text).expect("read stderr");
        }
        text
    }
}

fn free_loopback_addr() -> String {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral loopback")
        .local_addr()
        .expect("local addr")
        .to_string()
}

fn server_test_lock() -> MutexGuard<'static, ()> {
    static SERVER_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    SERVER_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("server test lock")
}

fn spawn_server(extra_args: &[&str]) -> ServeProcess {
    spawn_server_with_stderr(extra_args, Stdio::null())
}

fn spawn_server_with_stderr(extra_args: &[&str], stderr: Stdio) -> ServeProcess {
    let server_lock = server_test_lock();
    let addr = free_loopback_addr();
    let mut command = Command::new(bin());
    command
        .args(["serve", "--listen", &addr])
        .args(extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);
    let mut child = command.spawn().expect("spawn unicode-security serve");
    wait_for_server(&addr, &mut child);
    ServeProcess {
        child,
        addr,
        _server_lock: server_lock,
    }
}

#[cfg(unix)]
fn spawn_unix_server(extra_args: &[&str]) -> UnixServeProcess {
    let server_lock = server_test_lock();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "unicode-security-cli-{}-{}.sock",
        std::process::id(),
        unique
    ));
    let _ = fs::remove_file(&path);
    let mut command = Command::new(bin());
    command
        .args([
            "serve",
            "--unix-socket",
            path.to_str().expect("utf-8 unix socket path"),
        ])
        .args(extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("spawn unicode-security unix serve");
    wait_for_unix_server(&path, &mut child);
    UnixServeProcess {
        child,
        path,
        _server_lock: server_lock,
    }
}

fn wait_for_server(addr: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll server child") {
            panic!("server exited before listening on {addr}: {status}");
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("server did not listen on {addr}");
}

#[cfg(unix)]
fn wait_for_unix_server(path: &std::path::Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if UnixStream::connect(path).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll unix server child") {
            panic!(
                "server exited before listening on {}: {status}",
                path.display()
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("server did not listen on {}", path.display());
}

fn http_request(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect server");
    stream
        .write_all(request.as_bytes())
        .expect("write HTTP request");
    let _ = stream.shutdown(Shutdown::Write);
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err)
                if err.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() =>
            {
                break;
            }
            Err(err) => panic!("read HTTP response: {err}"),
        }
    }
    String::from_utf8(response).expect("response utf-8")
}

#[cfg(unix)]
fn http_request_unix(path: &std::path::Path, request: &str) -> String {
    let mut stream = UnixStream::connect(path).expect("connect unix server");
    stream
        .write_all(request.as_bytes())
        .expect("write HTTP request");
    let _ = stream.shutdown(Shutdown::Write);
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err)
                if err.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() =>
            {
                break;
            }
            Err(err) => panic!("read HTTP response: {err}"),
        }
    }
    String::from_utf8(response).expect("response utf-8")
}

fn http_post_scan(addr: &str, body: &str) -> String {
    http_request(
        addr,
        &format!(
            "POST /scan HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
    )
}

fn http_post_batch(addr: &str, body: &str) -> String {
    http_request(
        addr,
        &format!(
            "POST /batch HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
    )
}

struct CliEncodingCase {
    name: &'static str,
    encoding: &'static str,
    profile: &'static str,
    mode: &'static str,
    bytes: &'static [u8],
    status: i32,
    action: &'static str,
    input_fragment: &'static str,
    required_fragments: &'static [&'static str],
}

fn assert_cli_encoding_case(case: &CliEncodingCase) {
    let output = scan_file_json(
        case.name,
        Some(case.encoding),
        case.profile,
        case.mode,
        case.bytes,
    );
    assert_eq!(output.status.code(), Some(case.status), "{output:?}");
    assert_stdout_contains(&output, case.action);
    assert_stdout_contains(&output, case.input_fragment);
    for fragment in case.required_fragments {
        assert_stdout_contains(&output, fragment);
    }
}

#[test]
fn serve_healthz_returns_ready_json() {
    let server = spawn_server(&[]);
    let response = http_request(
        &server.addr,
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.ends_with("\r\n\r\n{\"status\":\"ok\"}"),
        "unexpected body={response}"
    );
}

#[test]
fn serve_scan_reuses_cli_policy_path() {
    let server = spawn_server(&["--profile", "source-code", "--mode", "strict"]);
    let response = http_post_scan(&server.addr, "{\"text\":\"a\u{200B}b\"}");

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("\"action\":\"reject\""),
        "missing reject action: {response}"
    );
    assert!(
        response.contains("\"code\":\"unicode.security.C.zero-width-payload.BareZeroWidth\""),
        "missing zero-width finding: {response}"
    );
    assert!(
        response.contains(
            "\"byte_spans\":[{\"cp_offset\":1,\"start_byte\":1,\"end_byte\":4,\"line\":1,\"column\":2}]"
        ),
        "missing byte span: {response}"
    );
}

#[test]
fn serve_rejects_request_policy_override_by_default() {
    let server = spawn_server(&[]);
    let response = http_post_scan(
        &server.addr,
        "{\"profile\":\"source-code\",\"text\":\"Hi\"}",
    );

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("profile override requires --allow-request-policy"),
        "missing override error: {response}"
    );
}

#[test]
fn serve_batch_processes_jsonl_records() {
    let server = spawn_server(&["--profile", "source-code", "--mode", "strict"]);
    let response = http_post_batch(
        &server.addr,
        "{\"id\":\"ok\",\"text\":\"Hi\"}\n{\"id\":\"bad\",\"text\":\"a\\u200Bb\"}\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("Content-Type: application/x-ndjson\r\n"),
        "missing ndjson content type: {response}"
    );
    assert!(
        response.contains(
            "{\"id\":\"ok\",\"action\":\"allow\",\"profile\":\"source-code\",\"mode\":\"strict\",\"input\":[72,105],\"findings\":[],\"normalized\":null}\n"
        ),
        "missing allow batch row: {response}"
    );
    assert!(
        response.contains("\"id\":\"bad\",\"action\":\"reject\""),
        "missing reject batch row: {response}"
    );
    assert!(
        response.contains("\"code\":\"unicode.security.C.zero-width-payload.BareZeroWidth\""),
        "missing zero-width finding: {response}"
    );
}

#[test]
fn serve_batch_rejects_policy_override_by_default() {
    let server = spawn_server(&[]);
    let response = http_post_batch(
        &server.addr,
        "{\"id\":\"bad\",\"profile\":\"source-code\",\"text\":\"Hi\"}\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("jsonl line 1: profile override requires --allow-request-policy"),
        "missing override error: {response}"
    );
}

#[test]
fn serve_batch_enforces_record_limit() {
    let server = spawn_server(&["--max-batch-records", "1"]);
    let response = http_post_batch(
        &server.addr,
        "{\"id\":\"a\",\"text\":\"Hi\"}\n{\"id\":\"b\",\"text\":\"Hi\"}\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("jsonl line 2: batch record count exceeds --max-batch-records (2 > 1)"),
        "missing record-limit error: {response}"
    );
}

#[test]
fn serve_accepts_request_timeout_option() {
    let server = spawn_server(&["--request-timeout-ms", "250"]);
    let response = http_request(
        &server.addr,
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
}

#[test]
fn serve_loads_policy_file_at_startup() {
    let path = temp_file(
        "serve-policy-startup.json",
        br#"{"profile":"source-code","mode":"strict","encoding":"utf-8","allow_request_policy":false}"#,
    );
    let policy_arg = path.to_str().expect("utf-8 path").to_string();
    let server = spawn_server(&["--policy-file", &policy_arg]);
    let response = http_post_scan(&server.addr, "{\"text\":\"a\\u200Bb\"}");
    let _ = fs::remove_file(path);

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("\"profile\":\"source-code\""),
        "missing policy-file profile: {response}"
    );
    assert!(
        response.contains("\"mode\":\"strict\""),
        "missing policy-file mode: {response}"
    );
    assert!(
        response.contains("\"action\":\"reject\""),
        "missing reject action: {response}"
    );
}

#[test]
fn serve_reloads_policy_file_per_request() {
    let path = temp_file(
        "serve-policy-reload.json",
        br#"{"profile":"source-code","mode":"observe","encoding":"utf-8","allow_request_policy":false}"#,
    );
    let policy_arg = path.to_str().expect("utf-8 path").to_string();
    let server = spawn_server(&["--policy-file", &policy_arg, "--reload-policy-per-request"]);

    let observed = http_post_scan(&server.addr, "{\"text\":\"a\\u200Bb\"}");
    assert!(
        observed.contains("\"action\":\"observe\""),
        "missing observe action before reload: {observed}"
    );

    fs::write(
        &path,
        br#"{"profile":"source-code","mode":"strict","encoding":"utf-8","allow_request_policy":false}"#,
    )
    .expect("rewrite policy file");
    let rejected = http_post_scan(&server.addr, "{\"text\":\"a\\u200Bb\"}");
    let _ = fs::remove_file(path);

    assert!(
        rejected.contains("\"action\":\"reject\""),
        "missing reject action after reload: {rejected}"
    );
}

#[test]
fn serve_invalid_reloaded_policy_fails_closed() {
    let path = temp_file(
        "serve-policy-invalid-reload.json",
        br#"{"profile":"source-code","mode":"observe","encoding":"utf-8","allow_request_policy":false}"#,
    );
    let policy_arg = path.to_str().expect("utf-8 path").to_string();
    let server = spawn_server(&["--policy-file", &policy_arg, "--reload-policy-per-request"]);

    fs::write(
        &path,
        br#"{"profile":"not-a-profile","mode":"strict","encoding":"utf-8","allow_request_policy":false}"#,
    )
    .expect("rewrite invalid policy file");
    let response = http_post_scan(&server.addr, "{\"text\":\"Hi\"}");
    let _ = fs::remove_file(path);

    assert!(
        response.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("policy reload failed"),
        "missing reload failure: {response}"
    );
}

#[test]
fn serve_request_logs_are_redacted() {
    let server = spawn_server_with_stderr(&["--log-requests"], Stdio::piped());
    let response = http_post_scan(&server.addr, "{\"text\":\"secret-a\\u200Bsecret-b\"}");
    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );

    let stderr = server.stop_and_stderr();
    assert!(
        stderr.contains("\"event\":\"request\""),
        "missing request log: {stderr}"
    );
    assert!(
        stderr.contains("\"path\":\"/scan\""),
        "missing path log: {stderr}"
    );
    assert!(
        stderr.contains("\"redacted\":true"),
        "missing redaction marker: {stderr}"
    );
    assert!(
        !stderr.contains("secret-a") && !stderr.contains("secret-b"),
        "payload leaked in stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn serve_unix_socket_reuses_http_policy_path() {
    let server = spawn_unix_server(&["--profile", "source-code", "--mode", "strict"]);
    let body = "{\"text\":\"a\\u200Bb\"}";
    let response = http_request_unix(
        &server.path,
        &format!(
            "POST /scan HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
    );

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("\"action\":\"reject\""),
        "missing reject action: {response}"
    );
    assert!(
        response.contains("unicode.security.C.zero-width-payload.BareZeroWidth"),
        "missing zero-width reason code: {response}"
    );
}

#[test]
fn serve_metrics_counts_scan_and_batch_verdicts() {
    let server = spawn_server(&["--profile", "source-code", "--mode", "strict"]);
    let _scan = http_post_scan(&server.addr, "{\"text\":\"a\u{200B}b\"}");
    let _batch = http_post_batch(
        &server.addr,
        "{\"id\":\"ok\",\"text\":\"Hi\"}\n{\"id\":\"bad\",\"text\":\"a\\u200Bb\"}\n",
    );
    let response = http_request(
        &server.addr,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("\"scan_requests_total\":1"),
        "missing scan count: {response}"
    );
    assert!(
        response.contains("\"batch_requests_total\":1"),
        "missing batch count: {response}"
    );
    assert!(
        response.contains("\"allow\":1"),
        "missing allow action count: {response}"
    );
    assert!(
        response.contains("\"reject\":2"),
        "missing reject action count: {response}"
    );
    assert!(
        response.contains("\"unicode.security.C.zero-width-payload.BareZeroWidth\":2"),
        "missing reason-code count: {response}"
    );
    assert!(
        response.contains("\"latency_ms\":{\"scan\":{\"count\":1"),
        "missing scan latency: {response}"
    );
    assert!(
        response.contains("\"batch\":{\"count\":1"),
        "missing batch latency: {response}"
    );
    assert!(
        response.contains("\"buckets\":{\"le_1\""),
        "missing latency buckets: {response}"
    );
}

#[test]
fn serve_metrics_counts_policy_reload_latency() {
    let policy_path = temp_file(
        "serve-policy-reload-latency.json",
        br#"{"profile":"source-code","mode":"strict","encoding":"utf-8","allow_request_policy":false}"#,
    );
    let policy_arg = policy_path.to_str().expect("utf-8 policy path").to_string();
    let server = spawn_server(&["--policy-file", &policy_arg, "--reload-policy-per-request"]);
    let _scan = http_post_scan(&server.addr, "{\"text\":\"Hi\"}");
    let response = http_request(
        &server.addr,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let _ = fs::remove_file(policy_path);

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response={response}"
    );
    assert!(
        response.contains("\"policy_reload\":{\"count\":1"),
        "missing policy reload latency: {response}"
    );
}

#[test]
fn serve_stdio_jsonl_processes_framed_records() {
    let output = run_stdio_jsonl_server(
        b"{\"id\":\"ok\",\"text\":\"Hi\"}\n{\"id\":\"bad\",\"text\":\"a\\u200Bb\"}\n",
        &["--profile", "source-code", "--mode", "strict"],
    );

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = stdout_text(&output);
    assert!(
        stdout.contains("\"id\":\"ok\"") && stdout.contains("\"action\":\"allow\""),
        "missing allow frame: {stdout}"
    );
    assert!(
        stdout.contains("\"id\":\"bad\"") && stdout.contains("\"action\":\"reject\""),
        "missing reject frame: {stdout}"
    );
    assert!(
        stdout.contains("unicode.security.C.zero-width-payload.BareZeroWidth"),
        "missing reason code: {stdout}"
    );
}

#[test]
fn scan_file_json_allows_ascii() {
    let path = temp_file("ascii.txt", b"Hello");
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "gateway-header",
            "--mode",
            "enforce",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("ascii_gateway_enforce.stdout.json")
    );
}

#[test]
fn scan_file_json_rejects_zero_width_in_strict_source() {
    let path = temp_file("zwsp.txt", "a\u{200B}b".as_bytes());
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "source-code",
            "--mode",
            "strict",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("source_zero_width_strict.stdout.json")
    );
}

#[test]
fn scan_file_json_reports_line_and_column() {
    let path = temp_file("zwsp-line.txt", "a\n\u{200B}".as_bytes());
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "source-code",
            "--mode",
            "strict",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("line_column_zero_width.stdout.json")
    );
}

#[test]
fn scan_file_json_rejects_utf16le_zero_width() {
    let path = temp_file("zwsp-utf16le.txt", &[0x61, 0x00, 0x0B, 0x20, 0x62, 0x00]);
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "source-code",
            "--mode",
            "strict",
            "--encoding",
            "utf-16le",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("source_zero_width_utf16le_strict.stdout.json")
    );
}

#[test]
fn scan_file_json_rejects_bom_utf16be_zero_width() {
    let path = temp_file(
        "zwsp-bom-utf16be.txt",
        &[0xFE, 0xFF, 0x00, 0x61, 0x20, 0x0B, 0x00, 0x62],
    );
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "source-code",
            "--mode",
            "strict",
            "--encoding",
            "bom",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("source_zero_width_bom_utf16be_strict.stdout.json")
    );
}

#[test]
fn scan_file_json_allows_utf32le_ascii() {
    let path = temp_file(
        "ascii-utf32le.txt",
        &[
            0x48, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x6C, 0x00,
            0x00, 0x00, 0x6F, 0x00, 0x00, 0x00,
        ],
    );
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "gateway-header",
            "--mode",
            "enforce",
            "--encoding",
            "utf-32le",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("ascii_gateway_enforce.stdout.json")
    );
}

#[test]
fn scan_file_json_rejects_malformed_utf16le() {
    let path = temp_file("malformed-utf16le.bin", &[0x61]);
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "gateway-header",
            "--mode",
            "enforce",
            "--encoding",
            "utf-16le",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("malformed_utf16le_enforce.stdout.json")
    );
}

#[test]
fn scan_file_json_covers_multiencoding_decode_contract() {
    let cases = [
        CliEncodingCase {
            name: "ascii-utf16be.txt",
            encoding: "utf-16be",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0, 72, 0, 101, 0, 108, 0, 108, 0, 111],
            status: 0,
            action: "\"action\":\"allow\"",
            input_fragment: "\"input\":[72,101,108,108,111]",
            required_fragments: &["\"findings\":[]"],
        },
        CliEncodingCase {
            name: "lone-surrogate-utf16be.bin",
            encoding: "utf-16be",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0xDC, 0x00],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.malformed-utf16.LoneSurrogate\"",
                "\"positions\":[0]",
                "\"byte_spans\":[{\"cp_offset\":null,\"start_byte\":0,\"end_byte\":2,\"line\":1,\"column\":1}]",
            ],
        },
        CliEncodingCase {
            name: "invalid-surrogate-pair-utf16le.bin",
            encoding: "utf-16le",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0x00, 0xD8, 0x41, 0x00],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.malformed-utf16.InvalidSurrogatePair\"",
                "\"positions\":[2]",
                "\"byte_spans\":[{\"cp_offset\":null,\"start_byte\":2,\"end_byte\":4,\"line\":1,\"column\":1}]",
            ],
        },
        CliEncodingCase {
            name: "truncated-surrogate-pair-utf16le.bin",
            encoding: "utf-16le",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0x00, 0xD8],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.malformed-utf16.TruncatedSurrogatePair\"",
                "\"positions\":[2]",
                "\"byte_spans\":[{\"cp_offset\":null,\"start_byte\":2,\"end_byte\":2,\"line\":1,\"column\":1}]",
            ],
        },
        CliEncodingCase {
            name: "ascii-utf32be.txt",
            encoding: "utf-32be",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[
                0, 0, 0, 72, 0, 0, 0, 101, 0, 0, 0, 108, 0, 0, 0, 108, 0, 0, 0, 111,
            ],
            status: 0,
            action: "\"action\":\"allow\"",
            input_fragment: "\"input\":[72,101,108,108,111]",
            required_fragments: &["\"findings\":[]"],
        },
        CliEncodingCase {
            name: "truncated-code-unit-utf32be.bin",
            encoding: "utf-32be",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0x00, 0x00, 0x00],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.malformed-utf32.TruncatedCodeUnit\"",
                "\"positions\":[3]",
                "\"byte_spans\":[{\"cp_offset\":null,\"start_byte\":3,\"end_byte\":3,\"line\":1,\"column\":1}]",
            ],
        },
        CliEncodingCase {
            name: "surrogate-codepoint-utf32le.bin",
            encoding: "utf-32le",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0x00, 0xD8, 0x00, 0x00],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.malformed-utf32.SurrogateCodepoint\"",
                "\"positions\":[0]",
                "\"byte_spans\":[{\"cp_offset\":null,\"start_byte\":0,\"end_byte\":4,\"line\":1,\"column\":1}]",
            ],
        },
        CliEncodingCase {
            name: "beyond-max-utf32be.bin",
            encoding: "utf-32be",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0x00, 0x11, 0x00, 0x00],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.malformed-utf32.CodepointBeyondMax\"",
                "\"positions\":[0]",
                "\"byte_spans\":[{\"cp_offset\":null,\"start_byte\":0,\"end_byte\":4,\"line\":1,\"column\":1}]",
            ],
        },
    ];

    for case in cases {
        assert_cli_encoding_case(&case);
    }
}

#[test]
fn scan_file_json_detects_bom_encodings_and_preserves_byte_offsets() {
    let cases = [
        CliEncodingCase {
            name: "bom-utf8-ascii.txt",
            encoding: "bom",
            profile: "gateway-header",
            mode: "enforce",
            bytes: &[0xEF, 0xBB, 0xBF, b'H', b'e', b'l', b'l', b'o'],
            status: 0,
            action: "\"action\":\"allow\"",
            input_fragment: "\"input\":[72,101,108,108,111]",
            required_fragments: &["\"findings\":[]"],
        },
        CliEncodingCase {
            name: "bom-utf16le-zero-width.bin",
            encoding: "bom",
            profile: "source-code",
            mode: "strict",
            bytes: &[0xFF, 0xFE, 0x61, 0x00, 0x0B, 0x20, 0x62, 0x00],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[97,8203,98]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.zero-width-payload.BareZeroWidth\"",
                "\"positions\":[1]",
                "\"byte_spans\":[{\"cp_offset\":1,\"start_byte\":4,\"end_byte\":6,\"line\":1,\"column\":2}]",
            ],
        },
        CliEncodingCase {
            name: "bom-utf32be-zero-width.bin",
            encoding: "bom",
            profile: "source-code",
            mode: "strict",
            bytes: &[
                0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x20, 0x0B, 0x00,
                0x00, 0x00, 0x62,
            ],
            status: 1,
            action: "\"action\":\"reject\"",
            input_fragment: "\"input\":[97,8203,98]",
            required_fragments: &[
                "\"code\":\"unicode.security.C.zero-width-payload.BareZeroWidth\"",
                "\"positions\":[1]",
                "\"byte_spans\":[{\"cp_offset\":1,\"start_byte\":8,\"end_byte\":12,\"line\":1,\"column\":2}]",
            ],
        },
    ];

    for case in cases {
        assert_cli_encoding_case(&case);
    }
}

#[test]
fn scan_file_json_rejects_malformed_utf8() {
    let path = temp_file("malformed.bin", &[0x80]);
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "gateway-header",
            "--mode",
            "enforce",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("malformed_utf8_enforce.stdout.json")
    );
}

#[test]
fn scan_file_json_reports_truncated_utf8_at_eof() {
    let path = temp_file("truncated.bin", &[0xC2]);
    let output = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "gateway-header",
            "--mode",
            "enforce",
            "--input",
            path.to_str().expect("utf-8 path"),
            "--json",
        ])
        .output()
        .expect("run unicode-security");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("truncated_utf8_enforce.stdout.json")
    );
}

#[test]
fn scan_stdin_json_observes_findings() {
    let mut child = Command::new(bin())
        .args([
            "scan",
            "--profile",
            "gateway-header",
            "--mode",
            "observe",
            "--input",
            "-",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn unicode-security");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all("\u{E0041}\u{E0042}".as_bytes())
        .expect("write stdin");

    let output = child.wait_with_output().expect("wait unicode-security");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("tag_block_observe.stdout.json")
    );
}

#[test]
fn scan_jsonl_allows_batch_records() {
    let output =
        run_jsonl_input(b"{\"id\":\"a\",\"text\":\"Hi\"}\n{\"id\":\"b\",\"bytes\":[79,75]}\n");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("batch_allows_jsonl.stdout.jsonl")
    );
}

#[test]
fn scan_jsonl_processes_all_records_and_rejects_if_any_reject() {
    let output = run_jsonl_input(
        b"{\"id\":\"ok\",\"text\":\"Hello\"}\n{\"id\":\"bad\",\"profile\":\"source-code\",\"mode\":\"strict\",\"text\":\"a\\u200Bb\"}\n",
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf-8"),
        fixture("batch_mixed_jsonl.stdout.jsonl")
    );
}

#[test]
fn scan_jsonl_accepts_per_record_encoded_bytes() {
    let output = run_jsonl_input(
        b"{\"id\":\"u16\",\"profile\":\"source-code\",\"mode\":\"strict\",\"encoding\":\"utf-16le\",\"bytes\":[97,0,11,32,98,0]}\n{\"id\":\"u32\",\"encoding\":\"utf-32be\",\"bytes\":[0,0,0,72]}\n",
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let stdout = stdout_text(&output);
    assert!(
        stdout.contains("\"id\":\"u16\""),
        "missing u16 record\nstdout={stdout}"
    );
    assert!(
        stdout.contains("\"code\":\"unicode.security.C.zero-width-payload.BareZeroWidth\""),
        "missing zero-width finding\nstdout={stdout}"
    );
    assert!(
        stdout.contains(
            "\"byte_spans\":[{\"cp_offset\":1,\"start_byte\":2,\"end_byte\":4,\"line\":1,\"column\":2}]"
        ),
        "missing utf-16 byte span\nstdout={stdout}"
    );
    assert!(
        stdout.contains("\"id\":\"u32\""),
        "missing u32 record\nstdout={stdout}"
    );
    assert!(
        stdout.contains(
            "\"id\":\"u32\",\"action\":\"allow\",\"profile\":\"gateway-header\",\"mode\":\"enforce\",\"input\":[72],\"findings\":[],\"normalized\":null}"
        ),
        "missing utf-32 allow verdict\nstdout={stdout}"
    );
}

#[test]
fn scan_jsonl_decodes_json_surrogate_pair_escapes() {
    let output = run_jsonl_input(b"{\"id\":\"emoji\",\"text\":\"\\uD83D\\uDE00\"}\n");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        stdout_text(&output),
        "{\"id\":\"emoji\",\"action\":\"allow\",\"profile\":\"gateway-header\",\"mode\":\"enforce\",\"input\":[128512],\"findings\":[],\"normalized\":null}\n"
    );
}

#[test]
fn scan_jsonl_rejects_ambiguous_or_invalid_records() {
    let cases: &[(&[u8], &str)] = &[
        (
            b"{\"id\":\"x\",\"unknown\":\"y\",\"text\":\"Hi\"}\n",
            "unknown field: unknown",
        ),
        (
            b"{\"id\":\"a\",\"id\":\"b\",\"text\":\"Hi\"}\n",
            "duplicate field: id",
        ),
        (b"{\"bytes\":[72,]}\n", "trailing comma in byte array"),
        (
            b"{\"encoding\":\"utf-16le\",\"text\":\"Hi\"}\n",
            "record text requires utf-8 encoding; use bytes for utf-16le input",
        ),
        (
            b"{\"text\":\"\\uDE00\"}\n",
            "low surrogate without preceding high surrogate",
        ),
    ];

    for (input, error) in cases {
        let output = run_jsonl_input(input);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(
            stdout_text(&output).is_empty(),
            "unexpected stdout for {error:?}: {}",
            stdout_text(&output)
        );
        let stderr = stderr_text(&output);
        assert!(
            stderr.contains("jsonl line 1:"),
            "missing line context in stderr={stderr}"
        );
        assert!(
            stderr.contains(error),
            "missing error {error:?} in stderr={stderr}"
        );
    }
}
