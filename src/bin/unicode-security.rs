//! Command-line entry point for the runtime security scanner.

use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, Read, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::process;
use std::time::{Duration, Instant};

use unicode_rust::security::{
    family_slug, scan, scan_utf8, Action, Family, Finding, Mode, Profile, Verdict,
};
use unicode_rust::{bom, decode_to_codepoints, utf32, BomKind};

const LATENCY_BUCKETS_MS: [u128; 8] = [1, 5, 10, 25, 50, 100, 250, 1000];

const USAGE: &str = "\
Usage:
  unicode-security scan [--profile PROFILE] [--mode MODE] [--encoding ENCODING] [--input PATH|-] [--json]
  unicode-security scan --jsonl [--input PATH|-]
  unicode-security serve [--listen ADDR] [--profile PROFILE] [--mode MODE] [--encoding ENCODING]

Profiles:
  gateway-header, domain-name, dns-label, url, username, display-name,
  chat-message, source-code, opaque-secret, binary-blob

Modes:
  observe, warn, enforce, strict

Input:
  --input PATH reads bytes from a file. --input - or an omitted --input reads stdin.
  --jsonl reads newline-delimited JSON records. Each record may set id, text,
  bytes, profile, mode, and encoding.

Server:
  --listen ADDR defaults to 127.0.0.1:8787.
  --unix-socket PATH listens on a Unix domain socket instead of TCP.
  --max-request-bytes N defaults to 1048576.
  --max-batch-records N defaults to 1000.
  --request-timeout-ms N sets socket read/write deadlines.
  --policy-file PATH loads profile/mode/encoding/override policy from JSON.
  --reload-policy-per-request revalidates --policy-file before each request.
  --log-requests emits redacted JSON request logs to stderr.
  --stdio-jsonl reads newline-delimited scan frames from stdin and writes one
  newline-delimited verdict frame per input frame to stdout.
  GET /healthz returns readiness.
  POST /scan accepts compact JSON with exactly one of text or bytes.
  POST /batch accepts newline-delimited scan records.
  GET /metrics returns JSON counters.
  Request profile/mode overrides require --allow-request-policy.

Encodings:
  utf-8, utf-16be, utf-16le, utf-32be, utf-32le, bom
  --encoding bom detects and strips a leading BOM; when no BOM is present it uses utf-8.
";

#[derive(Debug)]
struct Config {
    profile: Profile,
    mode: Mode,
    encoding: InputEncoding,
    input: Input,
    json: bool,
    jsonl: bool,
}

#[derive(Debug)]
struct ServeConfig {
    listen: String,
    unix_socket: Option<String>,
    profile: Profile,
    mode: Mode,
    encoding: InputEncoding,
    max_request_bytes: usize,
    max_batch_records: usize,
    request_timeout: Option<Duration>,
    allow_request_policy: bool,
    policy_file: Option<String>,
    reload_policy_per_request: bool,
    log_requests: bool,
    stdio_jsonl: bool,
}

#[derive(Debug, Clone, Copy)]
struct ServePolicy {
    profile: Profile,
    mode: Mode,
    encoding: InputEncoding,
    allow_request_policy: bool,
}

#[derive(Debug)]
struct ServerState {
    config: ServeConfig,
    metrics: Metrics,
}

#[derive(Debug, Default)]
struct Metrics {
    requests_total: usize,
    scan_requests_total: usize,
    batch_requests_total: usize,
    bad_requests_total: usize,
    malformed_decode_total: usize,
    actions: BTreeMap<String, usize>,
    reason_codes: BTreeMap<String, usize>,
    scan_latency: LatencyStats,
    batch_latency: LatencyStats,
    policy_reload_latency: LatencyStats,
}

#[derive(Debug, Default)]
struct LatencyStats {
    count: usize,
    sum_ms: u128,
    max_ms: u128,
    buckets: [usize; LATENCY_BUCKETS_MS.len()],
    overflow: usize,
}

#[derive(Debug)]
struct ScanMetric {
    action: Action,
    reason_codes: Vec<String>,
    malformed_decode: bool,
}

#[derive(Debug)]
enum Input {
    Stdin,
    File(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputEncoding {
    Utf8,
    Utf16Be,
    Utf16Le,
    Utf32Be,
    Utf32Le,
    Bom,
}

impl InputEncoding {
    fn tag(self) -> &'static str {
        match self {
            InputEncoding::Utf8 => "utf-8",
            InputEncoding::Utf16Be => "utf-16be",
            InputEncoding::Utf16Le => "utf-16le",
            InputEncoding::Utf32Be => "utf-32be",
            InputEncoding::Utf32Le => "utf-32le",
            InputEncoding::Bom => "bom",
        }
    }
}

#[derive(Debug)]
enum CliScan {
    Verdict {
        verdict: Verdict,
        spans: Vec<ByteSpan>,
        malformed_spans: Vec<ByteSpan>,
    },
    DecodeError {
        action: Action,
        profile: Profile,
        mode: Mode,
        finding: DecodeFinding,
    },
}

#[derive(Debug)]
struct BatchRecord {
    id: Option<String>,
    profile: Profile,
    mode: Mode,
    encoding: InputEncoding,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct BatchOutput {
    body: String,
    metrics: Vec<ScanMetric>,
}

#[derive(Debug)]
struct BatchRowOutput {
    line: String,
    exit_code: i32,
    metric: ScanMetric,
}

#[derive(Debug)]
struct ScanRequest {
    profile: Profile,
    mode: Mode,
    encoding: InputEncoding,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct DecodeFinding {
    code: String,
    family: &'static str,
    severity: u8,
    positions: Vec<usize>,
    byte_spans: Vec<ByteSpan>,
    sub_threat: &'static str,
    detail: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct ByteSpan {
    cp_offset: Option<usize>,
    start_byte: usize,
    end_byte: usize,
    line: Option<usize>,
    column: Option<usize>,
}

fn main() {
    let outcome = run(env::args().skip(1).collect());
    match outcome {
        Ok(exit_code) => process::exit(exit_code),
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    }
}

fn run(args: Vec<String>) -> Result<i32, String> {
    if args.first().map(String::as_str) == Some("serve") {
        return run_server(parse_serve_args(&args)?);
    }

    let config = parse_args(args)?;
    let bytes = read_input(&config.input)?;

    if config.jsonl {
        return run_jsonl(config.profile, config.mode, config.encoding, &bytes);
    }

    let scan = scan_bytes(config.profile, config.mode, config.encoding, &bytes);
    match scan {
        CliScan::Verdict {
            verdict,
            spans,
            malformed_spans,
        } => {
            if config.json {
                println!("{}", verdict_json(&verdict, &spans, &malformed_spans));
            } else {
                print_verdict_human(&verdict);
            }
            Ok(exit_code_for_action(verdict.action))
        }
        CliScan::DecodeError {
            action,
            profile,
            mode,
            finding,
        } => {
            if config.json {
                println!("{}", decode_error_json(action, profile, mode, &finding));
            } else {
                print_decode_error_human(action, profile, mode, &finding);
            }
            Ok(exit_code_for_action(action))
        }
    }
}

fn parse_serve_args(args: &[String]) -> Result<ServeConfig, String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}");
        process::exit(0);
    }

    let mut listen = "127.0.0.1:8787".to_string();
    let mut listen_set = false;
    let mut unix_socket = None;
    let mut profile = Profile::GatewayHeader;
    let mut mode = Mode::Enforce;
    let mut encoding = InputEncoding::Utf8;
    let mut max_request_bytes = 1024 * 1024;
    let mut max_batch_records = 1000usize;
    let mut request_timeout = None;
    let mut allow_request_policy = false;
    let mut policy_file = None;
    let mut reload_policy_per_request = false;
    let mut log_requests = false;
    let mut stdio_jsonl = false;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                listen = args
                    .get(i + 1)
                    .ok_or_else(|| "--listen requires a value".to_string())?
                    .clone();
                listen_set = true;
                i += 2;
            }
            "--unix-socket" => {
                unix_socket = Some(
                    args.get(i + 1)
                        .ok_or_else(|| "--unix-socket requires a value".to_string())?
                        .clone(),
                );
                i += 2;
            }
            "--profile" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--profile requires a value".to_string())?;
                profile = parse_profile(value)?;
                i += 2;
            }
            "--mode" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--mode requires a value".to_string())?;
                mode = parse_mode(value)?;
                i += 2;
            }
            "--encoding" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--encoding requires a value".to_string())?;
                encoding = parse_encoding(value)?;
                i += 2;
            }
            "--max-request-bytes" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--max-request-bytes requires a value".to_string())?;
                max_request_bytes = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --max-request-bytes value: {err}"))?;
                if max_request_bytes == 0 {
                    return Err("--max-request-bytes must be greater than zero".to_string());
                }
                i += 2;
            }
            "--max-batch-records" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--max-batch-records requires a value".to_string())?;
                max_batch_records = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid --max-batch-records value: {err}"))?;
                if max_batch_records == 0 {
                    return Err("--max-batch-records must be greater than zero".to_string());
                }
                i += 2;
            }
            "--request-timeout-ms" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--request-timeout-ms requires a value".to_string())?;
                let millis = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --request-timeout-ms value: {err}"))?;
                if millis == 0 {
                    return Err("--request-timeout-ms must be greater than zero".to_string());
                }
                request_timeout = Some(Duration::from_millis(millis));
                i += 2;
            }
            "--allow-request-policy" => {
                allow_request_policy = true;
                i += 1;
            }
            "--policy-file" => {
                policy_file = Some(
                    args.get(i + 1)
                        .ok_or_else(|| "--policy-file requires a value".to_string())?
                        .clone(),
                );
                i += 2;
            }
            "--reload-policy-per-request" => {
                reload_policy_per_request = true;
                i += 1;
            }
            "--log-requests" => {
                log_requests = true;
                i += 1;
            }
            "--stdio-jsonl" => {
                stdio_jsonl = true;
                i += 1;
            }
            "--json" => {
                i += 1;
            }
            other => return Err(format!("unknown option: {other}\n\n{USAGE}")),
        }
    }
    if reload_policy_per_request && policy_file.is_none() {
        return Err("--reload-policy-per-request requires --policy-file".to_string());
    }
    if listen_set && unix_socket.is_some() {
        return Err("--listen and --unix-socket are mutually exclusive".to_string());
    }
    if stdio_jsonl && unix_socket.is_some() {
        return Err("--stdio-jsonl and --unix-socket are mutually exclusive".to_string());
    }
    if stdio_jsonl && listen_set {
        return Err("--stdio-jsonl and --listen are mutually exclusive".to_string());
    }

    let mut config = ServeConfig {
        listen,
        unix_socket,
        profile,
        mode,
        encoding,
        max_request_bytes,
        max_batch_records,
        request_timeout,
        allow_request_policy,
        policy_file,
        reload_policy_per_request,
        log_requests,
        stdio_jsonl,
    };
    if let Some(policy) = load_policy_file_for_config(&config)? {
        config.apply_policy(policy);
    }
    Ok(config)
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}");
        process::exit(0);
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("unicode-security {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    let Some(command) = args.first() else {
        return Err(USAGE.to_string());
    };
    if command != "scan" {
        return Err(format!("unknown command: {command}\n\n{USAGE}"));
    }

    let mut profile = Profile::GatewayHeader;
    let mut mode = Mode::Enforce;
    let mut encoding = InputEncoding::Utf8;
    let mut input = Input::Stdin;
    let mut json = false;
    let mut jsonl = false;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--profile requires a value".to_string())?;
                profile = parse_profile(value)?;
                i += 2;
            }
            "--mode" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--mode requires a value".to_string())?;
                mode = parse_mode(value)?;
                i += 2;
            }
            "--encoding" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--encoding requires a value".to_string())?;
                encoding = parse_encoding(value)?;
                i += 2;
            }
            "--input" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--input requires a value".to_string())?;
                input = if value == "-" {
                    Input::Stdin
                } else {
                    Input::File(value.clone())
                };
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--jsonl" => {
                jsonl = true;
                json = true;
                i += 1;
            }
            other => return Err(format!("unknown option: {other}\n\n{USAGE}")),
        }
    }

    Ok(Config {
        profile,
        mode,
        encoding,
        input,
        json,
        jsonl,
    })
}

fn parse_profile(value: &str) -> Result<Profile, String> {
    match value {
        "gateway-header" | "gatewayHeader" => Ok(Profile::GatewayHeader),
        "domain-name" | "domainName" => Ok(Profile::DomainName),
        "dns-label" | "dnsLabel" => Ok(Profile::DnsLabel),
        "url" => Ok(Profile::Url),
        "username" => Ok(Profile::Username),
        "display-name" | "displayName" => Ok(Profile::DisplayName),
        "chat-message" | "chatMessage" => Ok(Profile::ChatMessage),
        "source-code" | "sourceCode" => Ok(Profile::SourceCode),
        "opaque-secret" | "opaqueSecret" => Ok(Profile::OpaqueSecret),
        "binary-blob" | "binaryBlob" => Ok(Profile::BinaryBlob),
        _ => Err(format!("unknown profile: {value}")),
    }
}

fn parse_mode(value: &str) -> Result<Mode, String> {
    match value {
        "observe" => Ok(Mode::Observe),
        "warn" => Ok(Mode::Warn),
        "enforce" => Ok(Mode::Enforce),
        "strict" => Ok(Mode::Strict),
        _ => Err(format!("unknown mode: {value}")),
    }
}

fn parse_encoding(value: &str) -> Result<InputEncoding, String> {
    match value {
        "utf-8" | "utf8" => Ok(InputEncoding::Utf8),
        "utf-16be" | "utf16be" => Ok(InputEncoding::Utf16Be),
        "utf-16le" | "utf16le" => Ok(InputEncoding::Utf16Le),
        "utf-32be" | "utf32be" => Ok(InputEncoding::Utf32Be),
        "utf-32le" | "utf32le" => Ok(InputEncoding::Utf32Le),
        "bom" | "auto" => Ok(InputEncoding::Bom),
        _ => Err(format!("unknown encoding: {value}")),
    }
}

impl ServeConfig {
    fn policy(&self) -> ServePolicy {
        ServePolicy {
            profile: self.profile,
            mode: self.mode,
            encoding: self.encoding,
            allow_request_policy: self.allow_request_policy,
        }
    }

    fn apply_policy(&mut self, policy: ServePolicy) {
        self.profile = policy.profile;
        self.mode = policy.mode;
        self.encoding = policy.encoding;
        self.allow_request_policy = policy.allow_request_policy;
    }
}

fn load_policy_file_for_config(config: &ServeConfig) -> Result<Option<ServePolicy>, String> {
    let Some(path) = config.policy_file.as_deref() else {
        return Ok(None);
    };
    load_policy_file(path, config.policy())
        .map(Some)
        .map_err(|err| format!("invalid policy file {path}: {err}"))
}

fn load_policy_file(path: &str, base: ServePolicy) -> Result<ServePolicy, String> {
    let text =
        fs::read_to_string(path).map_err(|err| format!("failed to read policy file: {err}"))?;
    let fields = parse_flat_json_object(&text)?;
    validate_policy_file_fields(&fields)?;
    let profile = match json_string_field(&fields, "profile")? {
        Some(value) => parse_profile(value)?,
        None => base.profile,
    };
    let mode = match json_string_field(&fields, "mode")? {
        Some(value) => parse_mode(value)?,
        None => base.mode,
    };
    let encoding = match json_string_field(&fields, "encoding")? {
        Some(value) => parse_encoding(value)?,
        None => base.encoding,
    };
    let allow_request_policy = match json_bool_field(&fields, "allow_request_policy")? {
        Some(value) => value,
        None => base.allow_request_policy,
    };
    Ok(ServePolicy {
        profile,
        mode,
        encoding,
        allow_request_policy,
    })
}

fn validate_policy_file_fields(fields: &[JsonField]) -> Result<(), String> {
    let mut seen = Vec::new();
    for field in fields {
        match field.key.as_str() {
            "profile" | "mode" | "encoding" | "allow_request_policy" => {}
            _ => return Err(format!("unknown policy field: {}", field.key)),
        }
        if seen.iter().any(|key| *key == field.key.as_str()) {
            return Err(format!("duplicate policy field: {}", field.key));
        }
        seen.push(field.key.as_str());
    }
    Ok(())
}

fn read_input(input: &Input) -> Result<Vec<u8>, String> {
    match input {
        Input::Stdin => {
            let mut bytes = Vec::new();
            io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|err| format!("failed to read stdin: {err}"))?;
            Ok(bytes)
        }
        Input::File(path) => fs::read(path).map_err(|err| format!("failed to read {path}: {err}")),
    }
}

fn run_server(config: ServeConfig) -> Result<i32, String> {
    if config.stdio_jsonl {
        return run_stdio_jsonl_server(config);
    }
    if config.unix_socket.is_some() {
        #[cfg(unix)]
        {
            return run_unix_server(config);
        }
        #[cfg(not(unix))]
        {
            return Err("--unix-socket is only supported on Unix platforms".to_string());
        }
    }
    run_tcp_server(config)
}

fn run_tcp_server(config: ServeConfig) -> Result<i32, String> {
    let listener = TcpListener::bind(&config.listen)
        .map_err(|err| format!("failed to listen on {}: {err}", config.listen))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to read listener address: {err}"))?;
    eprintln!("unicode-security serve listening on {local_addr}");
    let mut state = ServerState {
        config,
        metrics: Metrics::default(),
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                configure_tcp_timeout(&stream, state.config.request_timeout)?;
                let _ = handle_http_connection(&mut state, &mut stream);
            }
            Err(err) => eprintln!("unicode-security serve accept error: {err}"),
        }
    }

    Ok(0)
}

#[cfg(unix)]
fn run_unix_server(config: ServeConfig) -> Result<i32, String> {
    let path = config
        .unix_socket
        .as_deref()
        .ok_or_else(|| "missing --unix-socket path".to_string())?
        .to_string();
    let listener =
        UnixListener::bind(&path).map_err(|err| format!("failed to listen on {path}: {err}"))?;
    eprintln!("unicode-security serve listening on unix:{path}");
    let mut state = ServerState {
        config,
        metrics: Metrics::default(),
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                configure_unix_timeout(&stream, state.config.request_timeout)?;
                let _ = handle_http_connection(&mut state, &mut stream);
            }
            Err(err) => eprintln!("unicode-security serve accept error: {err}"),
        }
    }

    Ok(0)
}

fn run_stdio_jsonl_server(config: ServeConfig) -> Result<i32, String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let reader = io::BufReader::new(stdin.lock());
    let mut metrics = Metrics::default();

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|err| format!("failed to read stdio-jsonl frame: {err}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > config.max_request_bytes {
            metrics.record_bad_request();
            writeln!(
                stdout,
                "{}",
                error_json(&format!(
                    "jsonl line {}: frame exceeds --max-request-bytes ({} > {})",
                    line_index + 1,
                    trimmed.len(),
                    config.max_request_bytes
                ))
            )
            .map_err(|err| format!("failed to write stdio-jsonl error frame: {err}"))?;
            stdout
                .flush()
                .map_err(|err| format!("failed to flush stdio-jsonl frame: {err}"))?;
            continue;
        }

        let started = Instant::now();
        let output = match current_serve_policy(&config) {
            Ok(policy) => match parse_batch_record(
                trimmed,
                policy.profile,
                policy.mode,
                policy.encoding,
                policy.allow_request_policy,
            ) {
                Ok(record) => {
                    let row = scan_batch_record(record);
                    metrics.record_scan_metric(&row.metric);
                    row.line
                }
                Err(err) => {
                    metrics.record_bad_request();
                    error_json(&format!("jsonl line {}: {err}", line_index + 1))
                }
            },
            Err(err) => {
                metrics.record_bad_request();
                error_json(&format!("policy reload failed: {err}"))
            }
        };
        metrics.scan_latency.record(started.elapsed());
        writeln!(stdout, "{output}")
            .map_err(|err| format!("failed to write stdio-jsonl frame: {err}"))?;
        stdout
            .flush()
            .map_err(|err| format!("failed to flush stdio-jsonl frame: {err}"))?;
    }

    Ok(0)
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn configure_tcp_timeout(stream: &TcpStream, timeout: Option<Duration>) -> Result<(), String> {
    if let Some(timeout) = timeout {
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| format!("failed to set read timeout: {err}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| format!("failed to set write timeout: {err}"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn configure_unix_timeout(stream: &UnixStream, timeout: Option<Duration>) -> Result<(), String> {
    if let Some(timeout) = timeout {
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| format!("failed to set read timeout: {err}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| format!("failed to set write timeout: {err}"))?;
    }
    Ok(())
}

fn handle_http_connection<S: Read + IoWrite>(
    state: &mut ServerState,
    stream: &mut S,
) -> Result<(), String> {
    let response = match read_http_request(stream, state.config.max_request_bytes) {
        Ok(request) => route_http_request(state, request),
        Err(err) => {
            state.metrics.record_bad_request();
            http_response(400, error_json(&err))
        }
    };
    write_http_response(stream, response)
}

fn read_http_request<S: Read>(stream: &mut S, max_body: usize) -> Result<HttpRequest, String> {
    let mut buffer = Vec::new();
    let mut scratch = [0u8; 1024];
    let header_limit = 16 * 1024;
    let header_end = loop {
        let read = stream
            .read(&mut scratch)
            .map_err(|err| format!("failed to read HTTP request: {err}"))?;
        if read == 0 {
            if buffer.is_empty() {
                return Err("empty HTTP request".to_string());
            }
            return Err("truncated HTTP headers".to_string());
        }
        buffer.extend_from_slice(&scratch[..read]);
        if let Some(index) = find_bytes(&buffer, b"\r\n\r\n") {
            break index;
        }
        if buffer.len() > header_limit {
            return Err("HTTP headers exceed size limit".to_string());
        }
    };

    let header_bytes = &buffer[..header_end];
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|err| format!("HTTP headers are not UTF-8: {err}"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| "missing HTTP path".to_string())?
        .to_string();
    let _version = request_parts
        .next()
        .ok_or_else(|| "missing HTTP version".to_string())?;
    if request_parts.next().is_some() {
        return Err("invalid HTTP request line".to_string());
    }

    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("invalid HTTP header".to_string());
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value
                .trim()
                .parse::<usize>()
                .map_err(|err| format!("invalid Content-Length: {err}"))?;
        }
    }
    if content_length > max_body {
        return Err(format!(
            "request body exceeds --max-request-bytes ({content_length} > {max_body})"
        ));
    }

    let body_start = header_end + 4;
    let mut body = buffer[body_start..].to_vec();
    while body.len() < content_length {
        let read = stream
            .read(&mut scratch)
            .map_err(|err| format!("failed to read HTTP body: {err}"))?;
        if read == 0 {
            return Err("truncated HTTP body".to_string());
        }
        body.extend_from_slice(&scratch[..read]);
        if body.len() > max_body {
            return Err(format!(
                "request body exceeds --max-request-bytes ({} > {max_body})",
                body.len()
            ));
        }
    }
    body.truncate(content_length);

    Ok(HttpRequest { method, path, body })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: String,
}

fn route_http_request(state: &mut ServerState, request: HttpRequest) -> HttpResponse {
    state.metrics.requests_total += 1;
    let method = request.method.clone();
    let request_bytes = request.body.len();
    let path = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str())
        .to_string();
    let response = match (request.method.as_str(), path.as_str()) {
        ("GET", "/healthz") => http_response(200, "{\"status\":\"ok\"}".to_string()),
        ("GET", "/metrics") => http_response(200, state.metrics.to_json()),
        ("POST", "/scan") => {
            state.metrics.scan_requests_total += 1;
            let started = Instant::now();
            match current_serve_policy_for_request(state) {
                Ok(policy) => match scan_http_body(policy, &request.body) {
                    Ok((body, metric)) => {
                        state.metrics.record_scan_metric(&metric);
                        state.metrics.scan_latency.record(started.elapsed());
                        http_response(200, body)
                    }
                    Err(err) => {
                        state.metrics.record_bad_request();
                        state.metrics.scan_latency.record(started.elapsed());
                        http_response(400, error_json(&err))
                    }
                },
                Err(err) => {
                    state.metrics.record_bad_request();
                    state.metrics.scan_latency.record(started.elapsed());
                    http_response(500, error_json(&format!("policy reload failed: {err}")))
                }
            }
        }
        ("POST", "/batch") => {
            state.metrics.batch_requests_total += 1;
            let started = Instant::now();
            match current_serve_policy_for_request(state) {
                Ok(policy) => match scan_http_batch_body(&state.config, policy, &request.body) {
                    Ok(output) => {
                        for metric in &output.metrics {
                            state.metrics.record_scan_metric(metric);
                        }
                        state.metrics.batch_latency.record(started.elapsed());
                        http_response_with_type(200, "application/x-ndjson", output.body)
                    }
                    Err(err) => {
                        state.metrics.record_bad_request();
                        state.metrics.batch_latency.record(started.elapsed());
                        http_response(400, error_json(&err))
                    }
                },
                Err(err) => {
                    state.metrics.record_bad_request();
                    state.metrics.batch_latency.record(started.elapsed());
                    http_response(500, error_json(&format!("policy reload failed: {err}")))
                }
            }
        }
        (_, "/healthz" | "/metrics" | "/scan" | "/batch") => {
            http_response(405, error_json("method not allowed for endpoint"))
        }
        _ => http_response(404, error_json("not found")),
    };
    if state.config.log_requests {
        log_redacted_request(&method, &path, request_bytes, &response);
    }
    response
}

fn current_serve_policy(config: &ServeConfig) -> Result<ServePolicy, String> {
    if config.reload_policy_per_request {
        Ok(load_policy_file_for_config(config)?.unwrap_or_else(|| config.policy()))
    } else {
        Ok(config.policy())
    }
}

fn current_serve_policy_for_request(state: &mut ServerState) -> Result<ServePolicy, String> {
    if state.config.reload_policy_per_request {
        let started = Instant::now();
        let result = load_policy_file_for_config(&state.config)
            .map(|policy| policy.unwrap_or_else(|| state.config.policy()));
        state
            .metrics
            .policy_reload_latency
            .record(started.elapsed());
        result
    } else {
        Ok(state.config.policy())
    }
}

fn log_redacted_request(method: &str, path: &str, request_bytes: usize, response: &HttpResponse) {
    let mut out = String::new();
    out.push('{');
    push_json_field(&mut out, "event", "request");
    out.push(',');
    push_json_field(&mut out, "method", method);
    out.push(',');
    push_json_field(&mut out, "path", path);
    let _ = write!(out, ",\"status\":{}", response.status);
    let _ = write!(out, ",\"request_bytes\":{}", request_bytes);
    let _ = write!(out, ",\"response_bytes\":{}", response.body.len());
    out.push_str(",\"redacted\":true}");
    eprintln!("{out}");
}

fn scan_http_body(policy: ServePolicy, body: &[u8]) -> Result<(String, ScanMetric), String> {
    let text = std::str::from_utf8(body)
        .map_err(|err| format!("scan request body is not UTF-8 JSON: {err}"))?;
    let request = parse_scan_request(text, policy)?;
    Ok(cli_scan_json_and_metric(scan_bytes(
        request.profile,
        request.mode,
        request.encoding,
        &request.bytes,
    )))
}

fn scan_http_batch_body(
    config: &ServeConfig,
    policy: ServePolicy,
    body: &[u8],
) -> Result<BatchOutput, String> {
    let text = std::str::from_utf8(body)
        .map_err(|err| format!("batch request body is not UTF-8 JSONL: {err}"))?;
    scan_jsonl_text(
        policy.profile,
        policy.mode,
        policy.encoding,
        text,
        policy.allow_request_policy,
        Some(config.max_batch_records),
    )
}

fn parse_scan_request(line: &str, policy: ServePolicy) -> Result<ScanRequest, String> {
    let fields = parse_flat_json_object(line)?;
    validate_scan_request_fields(&fields)?;

    let profile = match json_string_field(&fields, "profile")? {
        Some(value) => {
            let profile = parse_profile(value)?;
            if profile != policy.profile && !policy.allow_request_policy {
                return Err("profile override requires --allow-request-policy".to_string());
            }
            profile
        }
        None => policy.profile,
    };
    let mode = match json_string_field(&fields, "mode")? {
        Some(value) => {
            let mode = parse_mode(value)?;
            if mode != policy.mode && !policy.allow_request_policy {
                return Err("mode override requires --allow-request-policy".to_string());
            }
            mode
        }
        None => policy.mode,
    };
    let encoding = match json_string_field(&fields, "encoding")? {
        Some(value) => parse_encoding(value)?,
        None => policy.encoding,
    };
    let text = json_string_field(&fields, "text")?;
    let bytes_field = json_array_field(&fields, "bytes")?;
    let bytes = match (text, bytes_field) {
        (Some(_), Some(_)) => return Err("request must not set both text and bytes".to_string()),
        (Some(value), None) => {
            if encoding != InputEncoding::Utf8 {
                return Err(format!(
                    "request text requires utf-8 encoding; use bytes for {} input",
                    encoding.tag()
                ));
            }
            value.as_bytes().to_vec()
        }
        (None, Some(values)) => parse_byte_array(values)?,
        (None, None) => return Err("request must set text or bytes".to_string()),
    };

    Ok(ScanRequest {
        profile,
        mode,
        encoding,
        bytes,
    })
}

fn validate_scan_request_fields(fields: &[JsonField]) -> Result<(), String> {
    let mut seen = Vec::new();
    for field in fields {
        match field.key.as_str() {
            "text" | "bytes" | "profile" | "mode" | "encoding" => {}
            _ => return Err(format!("unknown field: {}", field.key)),
        }
        if seen.iter().any(|key| *key == field.key.as_str()) {
            return Err(format!("duplicate field: {}", field.key));
        }
        seen.push(field.key.as_str());
    }
    Ok(())
}

impl Metrics {
    fn record_bad_request(&mut self) {
        self.bad_requests_total += 1;
    }

    fn record_scan_metric(&mut self, metric: &ScanMetric) {
        *self
            .actions
            .entry(metric.action.tag().to_string())
            .or_insert(0) += 1;
        if metric.malformed_decode {
            self.malformed_decode_total += 1;
        }
        for code in &metric.reason_codes {
            *self.reason_codes.entry(code.clone()).or_insert(0) += 1;
        }
    }

    fn to_json(&self) -> String {
        let mut out = String::new();
        out.push('{');
        let _ = write!(out, "\"requests_total\":{}", self.requests_total);
        let _ = write!(out, ",\"scan_requests_total\":{}", self.scan_requests_total);
        let _ = write!(
            out,
            ",\"batch_requests_total\":{}",
            self.batch_requests_total
        );
        let _ = write!(out, ",\"bad_requests_total\":{}", self.bad_requests_total);
        let _ = write!(
            out,
            ",\"malformed_decode_total\":{}",
            self.malformed_decode_total
        );
        out.push_str(",\"actions\":");
        push_count_map(&mut out, &self.actions);
        out.push_str(",\"reason_codes\":");
        push_count_map(&mut out, &self.reason_codes);
        out.push_str(",\"latency_ms\":{");
        out.push_str("\"scan\":");
        self.scan_latency.push_json(&mut out);
        out.push_str(",\"batch\":");
        self.batch_latency.push_json(&mut out);
        out.push_str(",\"policy_reload\":");
        self.policy_reload_latency.push_json(&mut out);
        out.push('}');
        out.push('}');
        out
    }
}

impl LatencyStats {
    fn record(&mut self, duration: Duration) {
        let ms = duration.as_micros().div_ceil(1000);
        self.count += 1;
        self.sum_ms += ms;
        self.max_ms = self.max_ms.max(ms);
        let mut bucketed = false;
        for (index, bucket) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if ms <= *bucket {
                self.buckets[index] += 1;
                bucketed = true;
                break;
            }
        }
        if !bucketed {
            self.overflow += 1;
        }
    }

    fn push_json(&self, out: &mut String) {
        out.push('{');
        let _ = write!(out, "\"count\":{}", self.count);
        let _ = write!(out, ",\"sum_ms\":{}", self.sum_ms);
        let _ = write!(out, ",\"max_ms\":{}", self.max_ms);
        out.push_str(",\"buckets\":{");
        for (index, bucket) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(out, "\"le_{bucket}\":{}", self.buckets[index]);
        }
        let _ = write!(out, ",\"gt_1000\":{}", self.overflow);
        out.push_str("}}");
    }
}

fn push_count_map(out: &mut String, values: &BTreeMap<String, usize>) {
    out.push('{');
    for (index, (key, value)) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(out, key);
        let _ = write!(out, ":{value}");
    }
    out.push('}');
}

fn cli_scan_json_and_metric(scan: CliScan) -> (String, ScanMetric) {
    match scan {
        CliScan::Verdict {
            verdict,
            spans,
            malformed_spans,
        } => {
            let metric = metric_from_verdict(&verdict);
            (verdict_json(&verdict, &spans, &malformed_spans), metric)
        }
        CliScan::DecodeError {
            action,
            profile,
            mode,
            finding,
        } => {
            let metric = metric_from_decode_error(action, &finding);
            (decode_error_json(action, profile, mode, &finding), metric)
        }
    }
}

fn metric_from_verdict(verdict: &Verdict) -> ScanMetric {
    ScanMetric {
        action: verdict.action,
        reason_codes: verdict
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect(),
        malformed_decode: verdict
            .findings
            .iter()
            .any(|finding| is_malformed_family(finding.family)),
    }
}

fn metric_from_decode_error(action: Action, finding: &DecodeFinding) -> ScanMetric {
    ScanMetric {
        action,
        reason_codes: vec![finding.code.clone()],
        malformed_decode: true,
    }
}

fn is_malformed_family(family: Family) -> bool {
    matches!(
        family,
        Family::MalformedUtf8 | Family::MalformedUtf16 | Family::MalformedUtf32
    )
}

fn http_response(status: u16, body: String) -> HttpResponse {
    http_response_with_type(status, "application/json", body)
}

fn http_response_with_type(status: u16, content_type: &'static str, body: String) -> HttpResponse {
    HttpResponse {
        status,
        content_type,
        body,
    }
}

fn write_http_response<S: IoWrite>(stream: &mut S, response: HttpResponse) -> Result<(), String> {
    let status_text = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {} {status_text}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(response.body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|err| format!("failed to write HTTP response: {err}"))
}

fn error_json(message: &str) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_field(&mut out, "error", message);
    out.push('}');
    out
}

fn run_jsonl(
    default_profile: Profile,
    default_mode: Mode,
    default_encoding: InputEncoding,
    bytes: &[u8],
) -> Result<i32, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|err| format!("jsonl input is not UTF-8: {err}"))?;
    let mut exit_code = 0;

    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record = parse_batch_record(
            trimmed,
            default_profile,
            default_mode,
            default_encoding,
            true,
        )
        .map_err(|err| format!("jsonl line {}: {err}", line_index + 1))?;
        let row = scan_batch_record(record);
        println!("{}", row.line);
        exit_code = exit_code.max(row.exit_code);
    }

    Ok(exit_code)
}

fn scan_jsonl_text(
    default_profile: Profile,
    default_mode: Mode,
    default_encoding: InputEncoding,
    text: &str,
    allow_policy_override: bool,
    max_records: Option<usize>,
) -> Result<BatchOutput, String> {
    let mut body = String::new();
    let mut metrics = Vec::new();
    let mut record_count = 0usize;

    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        record_count += 1;
        if let Some(max_records) = max_records {
            if record_count > max_records {
                return Err(format!(
                    "jsonl line {}: batch record count exceeds --max-batch-records ({} > {})",
                    line_index + 1,
                    record_count,
                    max_records
                ));
            }
        }

        let record = parse_batch_record(
            trimmed,
            default_profile,
            default_mode,
            default_encoding,
            allow_policy_override,
        )
        .map_err(|err| format!("jsonl line {}: {err}", line_index + 1))?;
        let row = scan_batch_record(record);
        metrics.push(row.metric);
        body.push_str(&row.line);
        body.push('\n');
    }

    Ok(BatchOutput { body, metrics })
}

fn scan_batch_record(record: BatchRecord) -> BatchRowOutput {
    let scan = scan_bytes(record.profile, record.mode, record.encoding, &record.bytes);
    match scan {
        CliScan::Verdict {
            verdict,
            spans,
            malformed_spans,
        } => {
            let exit_code = exit_code_for_action(verdict.action);
            let metric = metric_from_verdict(&verdict);
            let line = batch_verdict_json(record.id.as_deref(), &verdict, &spans, &malformed_spans);
            BatchRowOutput {
                line,
                exit_code,
                metric,
            }
        }
        CliScan::DecodeError {
            action,
            profile,
            mode,
            finding,
        } => {
            let exit_code = exit_code_for_action(action);
            let metric = metric_from_decode_error(action, &finding);
            let line =
                batch_decode_error_json(record.id.as_deref(), action, profile, mode, &finding);
            BatchRowOutput {
                line,
                exit_code,
                metric,
            }
        }
    }
}

fn parse_batch_record(
    line: &str,
    default_profile: Profile,
    default_mode: Mode,
    default_encoding: InputEncoding,
    allow_policy_override: bool,
) -> Result<BatchRecord, String> {
    let fields = parse_flat_json_object(line)?;
    validate_batch_fields(&fields)?;
    let id = json_string_field(&fields, "id")?.map(str::to_string);
    let profile = match json_string_field(&fields, "profile")? {
        Some(value) => {
            let profile = parse_profile(value)?;
            if profile != default_profile && !allow_policy_override {
                return Err("profile override requires --allow-request-policy".to_string());
            }
            profile
        }
        None => default_profile,
    };
    let mode = match json_string_field(&fields, "mode")? {
        Some(value) => {
            let mode = parse_mode(value)?;
            if mode != default_mode && !allow_policy_override {
                return Err("mode override requires --allow-request-policy".to_string());
            }
            mode
        }
        None => default_mode,
    };
    let encoding = match json_string_field(&fields, "encoding")? {
        Some(value) => parse_encoding(value)?,
        None => default_encoding,
    };
    let text = json_string_field(&fields, "text")?;
    let bytes_field = json_array_field(&fields, "bytes")?;
    let bytes = match (text, bytes_field) {
        (Some(_), Some(_)) => return Err("record must not set both text and bytes".to_string()),
        (Some(value), None) => {
            if encoding != InputEncoding::Utf8 {
                return Err(format!(
                    "record text requires utf-8 encoding; use bytes for {} input",
                    encoding.tag()
                ));
            }
            value.as_bytes().to_vec()
        }
        (None, Some(values)) => parse_byte_array(values)?,
        (None, None) => return Err("record must set text or bytes".to_string()),
    };

    Ok(BatchRecord {
        id,
        profile,
        mode,
        encoding,
        bytes,
    })
}

fn validate_batch_fields(fields: &[JsonField]) -> Result<(), String> {
    let mut seen = Vec::new();
    for field in fields {
        match field.key.as_str() {
            "id" | "text" | "bytes" | "profile" | "mode" | "encoding" => {}
            _ => return Err(format!("unknown field: {}", field.key)),
        }
        if seen.iter().any(|key| *key == field.key.as_str()) {
            return Err(format!("duplicate field: {}", field.key));
        }
        seen.push(field.key.as_str());
    }
    Ok(())
}

#[derive(Debug)]
struct JsonField {
    key: String,
    value: JsonValue,
}

#[derive(Debug)]
enum JsonValue {
    String(String),
    Array(Vec<usize>),
    Bool(bool),
}

fn parse_flat_json_object(line: &str) -> Result<Vec<JsonField>, String> {
    let mut parser = JsonParser::new(line);
    parser.parse_object()
}

struct JsonParser<'a> {
    input: &'a [u8],
    index: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            index: 0,
        }
    }

    fn parse_object(&mut self) -> Result<Vec<JsonField>, String> {
        self.skip_ws();
        self.expect(b'{')?;
        let mut fields = Vec::new();
        loop {
            self.skip_ws();
            if self.consume(b'}') {
                break;
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            fields.push(JsonField { key, value });
            self.skip_ws();
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        self.skip_ws();
        if self.index != self.input.len() {
            return Err("trailing data after JSON object".to_string());
        }
        Ok(fields)
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b'[') => Ok(JsonValue::Array(self.parse_number_array()?)),
            Some(b't') | Some(b'f') => Ok(JsonValue::Bool(self.parse_bool()?)),
            _ => Err("expected string, boolean, or byte array value".to_string()),
        }
    }

    fn parse_bool(&mut self) -> Result<bool, String> {
        if self.consume_bytes(b"true") {
            return Ok(true);
        }
        if self.consume_bytes(b"false") {
            return Ok(false);
        }
        Err("expected boolean value".to_string())
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        while let Some(byte) = self.next() {
            match byte {
                b'"' => return Ok(out),
                b'\\' => out.push(self.parse_escape()?),
                0x00..=0x1F => return Err("control character in JSON string".to_string()),
                _ => {
                    let start = self.index - 1;
                    while let Some(next) = self.peek() {
                        if next == b'"' || next == b'\\' || next <= 0x1F {
                            break;
                        }
                        self.index += 1;
                    }
                    let chunk = std::str::from_utf8(&self.input[start..self.index])
                        .map_err(|err| format!("invalid UTF-8 in JSON string: {err}"))?;
                    out.push_str(chunk);
                }
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_escape(&mut self) -> Result<char, String> {
        match self.next() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{0008}'),
            Some(b'f') => Ok('\u{000C}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => self.parse_unicode_escape(),
            _ => Err("invalid JSON string escape".to_string()),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        let cp = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&cp) {
            if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                return Err("high surrogate must be followed by low surrogate escape".to_string());
            }
            let low = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err("high surrogate must be followed by low surrogate escape".to_string());
            }
            let scalar = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
            return char::from_u32(scalar)
                .ok_or_else(|| "invalid surrogate-pair scalar".to_string());
        }
        if (0xDC00..=0xDFFF).contains(&cp) {
            return Err("low surrogate without preceding high surrogate".to_string());
        }
        char::from_u32(cp).ok_or_else(|| "invalid \\u escape scalar".to_string())
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let Some(byte) = self.next() else {
                return Err("truncated \\u escape".to_string());
            };
            value = (value << 4)
                | match byte {
                    b'0'..=b'9' => u32::from(byte - b'0'),
                    b'a'..=b'f' => u32::from(byte - b'a' + 10),
                    b'A'..=b'F' => u32::from(byte - b'A' + 10),
                    _ => return Err("invalid hex digit in \\u escape".to_string()),
                };
        }
        Ok(value)
    }

    fn parse_number_array(&mut self) -> Result<Vec<usize>, String> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.skip_ws();
        if self.consume(b']') {
            return Ok(values);
        }
        loop {
            values.push(self.parse_usize()?);
            self.skip_ws();
            if self.consume(b']') {
                break;
            }
            self.expect(b',')?;
            self.skip_ws();
            if self.peek() == Some(b']') {
                return Err("trailing comma in byte array".to_string());
            }
        }
        Ok(values)
    }

    fn parse_usize(&mut self) -> Result<usize, String> {
        self.skip_ws();
        let start = self.index;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.index += 1;
        }
        if self.index == start {
            return Err("expected unsigned byte value".to_string());
        }
        let text = std::str::from_utf8(&self.input[start..self.index]).expect("ascii digits");
        text.parse::<usize>()
            .map_err(|err| format!("invalid unsigned byte value: {err}"))
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(format!("expected '{}'", byte as char))
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn consume_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.input.get(self.index..self.index + bytes.len()) == Some(bytes) {
            self.index += bytes.len();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.index).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index += 1;
        Some(byte)
    }
}

fn json_string_field<'a>(fields: &'a [JsonField], key: &str) -> Result<Option<&'a str>, String> {
    let Some(field) = fields.iter().rev().find(|field| field.key == key) else {
        return Ok(None);
    };
    match &field.value {
        JsonValue::String(value) => Ok(Some(value)),
        JsonValue::Array(_) => Err(format!("field {key} must be a string")),
        JsonValue::Bool(_) => Err(format!("field {key} must be a string")),
    }
}

fn json_array_field<'a>(fields: &'a [JsonField], key: &str) -> Result<Option<&'a [usize]>, String> {
    let Some(field) = fields.iter().rev().find(|field| field.key == key) else {
        return Ok(None);
    };
    match &field.value {
        JsonValue::Array(values) => Ok(Some(values)),
        JsonValue::String(_) => Err(format!("field {key} must be a byte array")),
        JsonValue::Bool(_) => Err(format!("field {key} must be a byte array")),
    }
}

fn json_bool_field(fields: &[JsonField], key: &str) -> Result<Option<bool>, String> {
    let Some(field) = fields.iter().rev().find(|field| field.key == key) else {
        return Ok(None);
    };
    match &field.value {
        JsonValue::Bool(value) => Ok(Some(*value)),
        JsonValue::String(_) | JsonValue::Array(_) => Err(format!("field {key} must be a boolean")),
    }
}

fn parse_byte_array(values: &[usize]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(values.len());
    for &value in values {
        let byte = u8::try_from(value).map_err(|_| format!("byte value out of range: {value}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn scan_bytes(profile: Profile, mode: Mode, encoding: InputEncoding, bytes: &[u8]) -> CliScan {
    match encoding {
        InputEncoding::Utf8 => scan_utf8_bytes(profile, mode, bytes, 0),
        InputEncoding::Bom => scan_bom_bytes(profile, mode, bytes),
        InputEncoding::Utf16Be => scan_decoded(profile, mode, decode_utf16(bytes, Endian::Big, 0)),
        InputEncoding::Utf16Le => {
            scan_decoded(profile, mode, decode_utf16(bytes, Endian::Little, 0))
        }
        InputEncoding::Utf32Be => scan_decoded(profile, mode, decode_utf32(bytes, Endian::Big, 0)),
        InputEncoding::Utf32Le => {
            scan_decoded(profile, mode, decode_utf32(bytes, Endian::Little, 0))
        }
    }
}

fn scan_bom_bytes(profile: Profile, mode: Mode, bytes: &[u8]) -> CliScan {
    let (kind, content) = bom::strip(bytes);
    let base = bytes.len() - content.len();
    match kind {
        Some(BomKind::Utf8) | None => scan_utf8_bytes(profile, mode, content, base),
        Some(BomKind::Utf16BE) => {
            scan_decoded(profile, mode, decode_utf16(content, Endian::Big, base))
        }
        Some(BomKind::Utf16LE) => {
            scan_decoded(profile, mode, decode_utf16(content, Endian::Little, base))
        }
        Some(BomKind::Utf32BE) => {
            scan_decoded(profile, mode, decode_utf32(content, Endian::Big, base))
        }
        Some(BomKind::Utf32LE) => {
            scan_decoded(profile, mode, decode_utf32(content, Endian::Little, base))
        }
    }
}

fn scan_utf8_bytes(profile: Profile, mode: Mode, bytes: &[u8], base: usize) -> CliScan {
    let mut verdict = scan_utf8(profile, mode, bytes);
    if base != 0 {
        for finding in &mut verdict.findings {
            if finding.family == Family::MalformedUtf8 {
                for position in &mut finding.positions {
                    *position += base;
                }
            }
        }
    }
    let spans = if has_malformed_utf8(&verdict) {
        Vec::new()
    } else {
        codepoint_spans(&verdict.input, base)
    };
    let malformed_spans = malformed_utf8_byte_spans(&verdict, bytes, base);
    CliScan::Verdict {
        verdict,
        spans,
        malformed_spans,
    }
}

fn scan_decoded(
    profile: Profile,
    mode: Mode,
    decoded: Result<DecodedInput, DecodeFinding>,
) -> CliScan {
    match decoded {
        Ok(decoded) => {
            let verdict = scan(profile, mode, &decoded.cps);
            CliScan::Verdict {
                verdict,
                spans: decoded.spans,
                malformed_spans: Vec::new(),
            }
        }
        Err(finding) => CliScan::DecodeError {
            action: decode_error_action(mode),
            profile,
            mode,
            finding,
        },
    }
}

#[derive(Debug)]
struct DecodedInput {
    cps: Vec<u32>,
    spans: Vec<ByteSpan>,
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Big,
    Little,
}

fn decode_utf16(bytes: &[u8], endian: Endian, base: usize) -> Result<DecodedInput, DecodeFinding> {
    let mut cps = Vec::new();
    let mut spans = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let Some(unit) = read_u16(bytes, offset, endian) else {
            return Err(decode_error(
                "malformed-utf16",
                "TruncatedCodeUnit",
                base + bytes.len(),
                base + bytes.len(),
                &cps,
            ));
        };

        if (0xD800..=0xDBFF).contains(&unit) {
            let low_offset = offset + 2;
            let Some(low) = read_u16(bytes, low_offset, endian) else {
                return Err(decode_error(
                    "malformed-utf16",
                    "TruncatedSurrogatePair",
                    base + bytes.len(),
                    base + bytes.len(),
                    &cps,
                ));
            };
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(decode_error_with_end(
                    "malformed-utf16",
                    "InvalidSurrogatePair",
                    base + low_offset,
                    base + low_offset + 2,
                    &cps,
                ));
            }
            let cp = 0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
            cps.push(cp);
            spans.push(codepoint_span(
                cps.len() - 1,
                base + offset,
                base + offset + 4,
                &cps,
            ));
            offset += 4;
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(decode_error_with_end(
                "malformed-utf16",
                "LoneSurrogate",
                base + offset,
                base + offset + 2,
                &cps,
            ));
        } else {
            cps.push(u32::from(unit));
            spans.push(codepoint_span(
                cps.len() - 1,
                base + offset,
                base + offset + 2,
                &cps,
            ));
            offset += 2;
        }
    }

    Ok(DecodedInput { cps, spans })
}

fn decode_utf32(bytes: &[u8], endian: Endian, base: usize) -> Result<DecodedInput, DecodeFinding> {
    let mut cps = Vec::new();
    let mut spans = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if offset + 4 > bytes.len() {
            return Err(decode_error(
                "malformed-utf32",
                "TruncatedCodeUnit",
                base + bytes.len(),
                base + bytes.len(),
                &cps,
            ));
        }
        let cp = match endian {
            Endian::Big => utf32::decode_one_be(&bytes[offset..offset + 4]),
            Endian::Little => utf32::decode_one_le(&bytes[offset..offset + 4]),
        };
        let Some(cp) = cp else {
            let raw = match endian {
                Endian::Big => u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]),
                Endian::Little => u32::from_le_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]),
            };
            let sub_threat = if (0xD800..=0xDFFF).contains(&raw) {
                "SurrogateCodepoint"
            } else {
                "CodepointBeyondMax"
            };
            return Err(decode_error_with_end(
                "malformed-utf32",
                sub_threat,
                base + offset,
                base + offset + 4,
                &cps,
            ));
        };
        cps.push(cp);
        spans.push(codepoint_span(
            cps.len() - 1,
            base + offset,
            base + offset + 4,
            &cps,
        ));
        offset += 4;
    }

    Ok(DecodedInput { cps, spans })
}

fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    if offset + 2 > bytes.len() {
        return None;
    }
    Some(match endian {
        Endian::Big => u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
        Endian::Little => u16::from_le_bytes([bytes[offset], bytes[offset + 1]]),
    })
}

fn codepoint_span(cp_offset: usize, start_byte: usize, end_byte: usize, cps: &[u32]) -> ByteSpan {
    let (line, column) = position_for_codepoint(cps, cp_offset);
    ByteSpan {
        cp_offset: Some(cp_offset),
        start_byte,
        end_byte,
        line: Some(line),
        column: Some(column),
    }
}

fn decode_error(
    family: &'static str,
    sub_threat: &'static str,
    offset: usize,
    end_offset: usize,
    prefix_cps: &[u32],
) -> DecodeFinding {
    decode_error_with_end(family, sub_threat, offset, end_offset, prefix_cps)
}

fn decode_error_with_end(
    family: &'static str,
    sub_threat: &'static str,
    offset: usize,
    end_offset: usize,
    prefix_cps: &[u32],
) -> DecodeFinding {
    let position = position_after_codepoints(prefix_cps);
    DecodeFinding {
        code: format!("unicode.security.C.{family}.{sub_threat}"),
        family,
        severity: 2,
        positions: vec![offset],
        byte_spans: vec![ByteSpan {
            cp_offset: None,
            start_byte: offset,
            end_byte: end_offset,
            line: Some(position.0),
            column: Some(position.1),
        }],
        sub_threat,
        detail: family,
    }
}

fn position_after_codepoints(cps: &[u32]) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    for &cp in cps {
        if cp == 0x0A {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn position_for_codepoint(cps: &[u32], cp_offset: usize) -> (usize, usize) {
    position_after_codepoints(&cps[..cp_offset.min(cps.len())])
}

fn has_malformed_utf8(verdict: &Verdict) -> bool {
    verdict
        .findings
        .iter()
        .any(|finding| finding.family == Family::MalformedUtf8)
}

fn malformed_utf8_byte_spans(verdict: &Verdict, bytes: &[u8], base: usize) -> Vec<ByteSpan> {
    let mut spans = Vec::new();
    for finding in &verdict.findings {
        if finding.family != Family::MalformedUtf8 {
            continue;
        }
        let truncated = finding.sub_threat.as_deref() == Some("TruncatedSequence");
        for &offset in &finding.positions {
            let content_offset = offset.saturating_sub(base).min(bytes.len());
            let prefix_cps = decode_to_codepoints(&bytes[..content_offset]);
            let position = position_after_codepoints(&prefix_cps);
            spans.push(ByteSpan {
                cp_offset: None,
                start_byte: offset,
                end_byte: if truncated {
                    offset
                } else {
                    offset.saturating_add(1)
                },
                line: Some(position.0),
                column: Some(position.1),
            });
        }
    }
    spans
}

fn exit_code_for_action(action: Action) -> i32 {
    match action {
        Action::Allow | Action::Observe | Action::Rewrite => 0,
        Action::Reject | Action::Quarantine => 1,
    }
}

fn verdict_json(verdict: &Verdict, spans: &[ByteSpan], malformed_spans: &[ByteSpan]) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_field(&mut out, "action", verdict.action.tag());
    out.push(',');
    push_json_field(&mut out, "profile", verdict.profile.tag());
    out.push(',');
    push_json_field(&mut out, "mode", verdict.mode.tag());
    out.push(',');
    out.push_str("\"input\":");
    push_u32_array(&mut out, &verdict.input);
    out.push(',');
    out.push_str("\"findings\":");
    push_findings(&mut out, &verdict.findings, spans, malformed_spans);
    out.push(',');
    out.push_str("\"normalized\":");
    match &verdict.normalized {
        Some(cps) => push_u32_array(&mut out, cps),
        None => out.push_str("null"),
    }
    out.push('}');
    out
}

fn decode_error_json(
    action: Action,
    profile: Profile,
    mode: Mode,
    finding: &DecodeFinding,
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_field(&mut out, "action", action.tag());
    out.push(',');
    push_json_field(&mut out, "profile", profile.tag());
    out.push(',');
    push_json_field(&mut out, "mode", mode.tag());
    out.push(',');
    out.push_str("\"input\":[],\"findings\":[");
    push_decode_finding(&mut out, finding);
    out.push_str("],\"normalized\":null}");
    out
}

fn batch_verdict_json(
    id: Option<&str>,
    verdict: &Verdict,
    spans: &[ByteSpan],
    malformed_spans: &[ByteSpan],
) -> String {
    prepend_optional_id(id, verdict_json(verdict, spans, malformed_spans))
}

fn batch_decode_error_json(
    id: Option<&str>,
    action: Action,
    profile: Profile,
    mode: Mode,
    finding: &DecodeFinding,
) -> String {
    prepend_optional_id(id, decode_error_json(action, profile, mode, finding))
}

fn prepend_optional_id(id: Option<&str>, json: String) -> String {
    let Some(id) = id else {
        return json;
    };
    let mut out = String::new();
    out.push('{');
    push_json_field(&mut out, "id", id);
    if json == "{}" {
        out.push('}');
    } else {
        out.push(',');
        out.push_str(json.trim_start_matches('{'));
    }
    out
}

fn decode_error_action(mode: Mode) -> Action {
    match mode {
        Mode::Observe | Mode::Warn => Action::Observe,
        Mode::Enforce | Mode::Strict => Action::Reject,
    }
}

fn push_findings(
    out: &mut String,
    findings: &[Finding],
    spans: &[ByteSpan],
    malformed_spans: &[ByteSpan],
) {
    out.push('[');
    for (index, finding) in findings.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_finding(out, finding, spans, malformed_spans);
    }
    out.push(']');
}

fn push_finding(
    out: &mut String,
    finding: &Finding,
    spans: &[ByteSpan],
    malformed_spans: &[ByteSpan],
) {
    out.push('{');
    push_json_field(out, "code", &finding.code);
    out.push(',');
    push_json_field(out, "family", family_slug(finding.family));
    out.push(',');
    let _ = write!(out, "\"severity\":{}", finding.severity as u8);
    out.push(',');
    out.push_str("\"positions\":");
    push_usize_array(out, &finding.positions);
    out.push(',');
    out.push_str("\"byte_spans\":");
    if finding.family == Family::MalformedUtf8 {
        push_byte_spans(out, malformed_spans);
    } else {
        push_position_byte_spans(out, &finding.positions, spans);
    }
    out.push(',');
    out.push_str("\"sub_threat\":");
    match &finding.sub_threat {
        Some(sub_threat) => push_json_string(out, sub_threat),
        None => out.push_str("null"),
    }
    out.push(',');
    push_json_field(out, "detail", &finding.detail);
    out.push('}');
}

fn push_decode_finding(out: &mut String, finding: &DecodeFinding) {
    out.push('{');
    push_json_field(out, "code", &finding.code);
    out.push(',');
    push_json_field(out, "family", finding.family);
    out.push(',');
    let _ = write!(out, "\"severity\":{}", finding.severity);
    out.push(',');
    out.push_str("\"positions\":");
    push_usize_array(out, &finding.positions);
    out.push(',');
    out.push_str("\"byte_spans\":");
    push_byte_spans(out, &finding.byte_spans);
    out.push(',');
    push_json_field(out, "sub_threat", finding.sub_threat);
    out.push(',');
    push_json_field(out, "detail", finding.detail);
    out.push('}');
}

fn push_json_field(out: &mut String, key: &str, value: &str) {
    push_json_string(out, key);
    out.push(':');
    push_json_string(out, value);
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04X}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn push_u32_array(out: &mut String, values: &[u32]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
}

fn push_usize_array(out: &mut String, values: &[usize]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
}

fn push_position_byte_spans(out: &mut String, positions: &[usize], spans: &[ByteSpan]) {
    out.push('[');
    let mut written = 0usize;
    for position in positions {
        let Some(span) = spans.get(*position) else {
            continue;
        };
        if written > 0 {
            out.push(',');
        }
        push_byte_span(out, span);
        written += 1;
    }
    out.push(']');
}

fn push_byte_spans(out: &mut String, spans: &[ByteSpan]) {
    out.push('[');
    for (index, span) in spans.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_byte_span(out, span);
    }
    out.push(']');
}

fn push_byte_span(out: &mut String, span: &ByteSpan) {
    out.push('{');
    out.push_str("\"cp_offset\":");
    match span.cp_offset {
        Some(cp_offset) => {
            let _ = write!(out, "{cp_offset}");
        }
        None => out.push_str("null"),
    }
    out.push(',');
    let _ = write!(out, "\"start_byte\":{}", span.start_byte);
    out.push(',');
    let _ = write!(out, "\"end_byte\":{}", span.end_byte);
    out.push(',');
    out.push_str("\"line\":");
    match span.line {
        Some(line) => {
            let _ = write!(out, "{line}");
        }
        None => out.push_str("null"),
    }
    out.push(',');
    out.push_str("\"column\":");
    match span.column {
        Some(column) => {
            let _ = write!(out, "{column}");
        }
        None => out.push_str("null"),
    }
    out.push('}');
}

fn codepoint_spans(cps: &[u32], base: usize) -> Vec<ByteSpan> {
    let mut spans = Vec::with_capacity(cps.len());
    let mut byte = base;
    let mut line = 1usize;
    let mut column = 1usize;

    for (cp_offset, &cp) in cps.iter().enumerate() {
        let width = utf8_width(cp);
        spans.push(ByteSpan {
            cp_offset: Some(cp_offset),
            start_byte: byte,
            end_byte: byte + width,
            line: Some(line),
            column: Some(column),
        });
        byte += width;
        if cp == 0x0A {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    spans
}

fn utf8_width(cp: u32) -> usize {
    match cp {
        0x0000..=0x007F => 1,
        0x0080..=0x07FF => 2,
        0x0800..=0xFFFF => 3,
        _ => 4,
    }
}

fn print_verdict_human(verdict: &Verdict) {
    println!("action: {}", verdict.action.tag());
    println!("profile: {}", verdict.profile.tag());
    println!("mode: {}", verdict.mode.tag());
    if verdict.findings.is_empty() {
        println!("findings: none");
        return;
    }
    println!("findings:");
    for finding in &verdict.findings {
        println!("- {} positions={:?}", finding.code, finding.positions);
    }
}

fn print_decode_error_human(action: Action, profile: Profile, mode: Mode, finding: &DecodeFinding) {
    println!("action: {}", action.tag());
    println!("profile: {}", profile.tag());
    println!("mode: {}", mode.tag());
    println!("findings:");
    println!("- {} positions={:?}", finding.code, finding.positions);
}
