#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use native_tls::{Certificate, TlsConnector};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const ADAPTER_ID: &str = "metasploit";
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_RPC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CONSOLE_READ_BYTES: usize = 256 * 1024;

const READONLY_METHODS: &[&str] = &[
    "core.version",
    "module.info",
    "module.options",
    "module.search",
    "module.exploits",
    "module.auxiliary",
    "module.payloads",
    "module.encoders",
    "module.nops",
    "module.post",
    "module.evasion",
    "job.list",
    "session.list",
    "console.list",
    "db.workspaces",
];

#[derive(Debug, Error)]
pub enum MsfError {
    #[error("RPC endpoint must be loopback")]
    NonLoopback,
    #[error("RPC input or response failed validation")]
    InvalidData,
    #[error("RPC TLS certificate changed during the lifecycle")]
    TlsPin,
    #[error("RPC authentication failed")]
    Authentication,
    #[error("RPC returned HTTP status {0}")]
    Http(u16),
    #[error("RPC transport failed at {0}")]
    Transport(&'static str),
    #[error("automatic replay is forbidden for execution method {0}")]
    ReplayForbidden(String),
    #[error("RPC response exceeded its bound")]
    ResponseTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleSummary {
    pub module_type: String,
    pub fullname: String,
    pub name: String,
    pub rank: String,
    pub disclosure_date: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleOption {
    pub name: String,
    pub option_type: String,
    pub required: bool,
    pub advanced: bool,
    pub default: Option<serde_json::Value>,
    pub description: String,
    pub enums: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkVersion {
    pub version: String,
    pub ruby: String,
    pub api: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub job_id: Option<String>,
    pub uuid: Option<String>,
}

pub trait RpcTransport {
    fn invoke(&mut self, arguments: &[Value]) -> Result<Value, MsfError>;
    fn certificate_sha256(&self) -> Option<&str>;
}

pub struct HttpsMessagePackTransport {
    host: String,
    port: u16,
    timeout: Duration,
    certificate_sha256: Option<String>,
}

impl HttpsMessagePackTransport {
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, MsfError> {
        if host != "127.0.0.1" && host != "::1" {
            return Err(MsfError::NonLoopback);
        }
        if port == 0 || timeout.is_zero() {
            return Err(MsfError::InvalidData);
        }
        let mut transport = Self {
            host: host.to_owned(),
            port,
            timeout,
            certificate_sha256: None,
        };
        let certificate = transport.peer_certificate()?;
        transport.certificate_sha256 = Some(sha256(&certificate));
        Ok(transport)
    }

    fn peer_certificate(&self) -> Result<Vec<u8>, MsfError> {
        let (_, certificate) = self.tls_stream()?;
        certificate
            .to_der()
            .map_err(|_| MsfError::Transport("certificate_der"))
    }

    fn tls_stream(&self) -> Result<(native_tls::TlsStream<TcpStream>, Certificate), MsfError> {
        let address = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|_| MsfError::Transport("resolve"))?
            .find(|address| address.ip().is_loopback())
            .ok_or(MsfError::NonLoopback)?;
        let stream = TcpStream::connect_timeout(&address, self.timeout)
            .map_err(|_| MsfError::Transport("tcp_connect"))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| MsfError::Transport("read_timeout"))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| MsfError::Transport("write_timeout"))?;
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
            .build()
            .map_err(|_| MsfError::Transport("tls_builder"))?;
        let tls = connector
            .connect("localhost", stream)
            .map_err(|_| MsfError::Transport("tls_handshake"))?;
        let certificate = tls
            .peer_certificate()
            .map_err(|_| MsfError::Transport("peer_certificate"))?
            .ok_or(MsfError::Transport("peer_certificate_missing"))?;
        Ok((tls, certificate))
    }
}

impl RpcTransport for HttpsMessagePackTransport {
    fn invoke(&mut self, arguments: &[Value]) -> Result<Value, MsfError> {
        let mut body = Vec::with_capacity(1024);
        rmpv::encode::write_value(&mut body, &Value::Array(arguments.to_vec()))
            .map_err(|_| MsfError::InvalidData)?;
        let (mut stream, certificate) = self.tls_stream()?;
        let fingerprint = sha256(
            &certificate
                .to_der()
                .map_err(|_| MsfError::Transport("certificate_der"))?,
        );
        if self.certificate_sha256.as_deref() != Some(fingerprint.as_str()) {
            return Err(MsfError::TlsPin);
        }
        let headers = format!(
            "POST /api/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: binary/message-pack\r\nAccept: binary/message-pack\r\nConnection: close\r\nContent-Length: {}\r\nUser-Agent: FlagDeck/0.5\r\n\r\n",
            self.port,
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .map_err(|_| MsfError::Transport("write_request"))?;
        let response = read_bounded(&mut stream, MAX_RPC_RESPONSE_BYTES + 64 * 1024)?;
        let (status, payload) = parse_http_response(&response)?;
        if status != 200 {
            return Err(if status == 401 {
                MsfError::Authentication
            } else {
                MsfError::Http(status)
            });
        }
        let mut cursor = Cursor::new(payload);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| MsfError::InvalidData)?;
        if usize::try_from(cursor.position()).ok() != Some(payload.len()) {
            return Err(MsfError::InvalidData);
        }
        Ok(value)
    }

    fn certificate_sha256(&self) -> Option<&str> {
        self.certificate_sha256.as_deref()
    }
}

pub struct MsfRpcClient<T: RpcTransport> {
    transport: T,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
    pub reauth_count: u32,
    pub readonly_replay_count: u32,
}

impl<T: RpcTransport> MsfRpcClient<T> {
    pub fn new(transport: T, username: String, password: String) -> Result<Self, MsfError> {
        if username.is_empty() || password.len() < 32 {
            return Err(MsfError::InvalidData);
        }
        Ok(Self {
            transport,
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
            token: None,
            reauth_count: 0,
            readonly_replay_count: 0,
        })
    }

    pub fn login(&mut self) -> Result<(), MsfError> {
        let response = self.transport.invoke(&[
            Value::from("auth.login"),
            Value::from(self.username.as_str()),
            Value::from(self.password.as_str()),
        ])?;
        let map = map(&response)?;
        if string_value(map.get("result")) != Some("success") {
            return Err(MsfError::Authentication);
        }
        let token = string_value(map.get("token"))
            .ok_or(MsfError::Authentication)?
            .to_owned();
        self.token = Some(Zeroizing::new(token));
        Ok(())
    }

    pub fn logout(&mut self) -> Result<(), MsfError> {
        let token = self
            .token
            .as_ref()
            .ok_or(MsfError::Authentication)?
            .to_string();
        let response = self.call_once("auth.logout", &[Value::from(token)])?;
        if string_value(map(&response)?.get("result")) != Some("success") {
            return Err(MsfError::Authentication);
        }
        if let Some(mut token) = self.token.take() {
            token.zeroize();
        }
        Ok(())
    }

    pub fn call_readonly(&mut self, method: &str, args: &[Value]) -> Result<Value, MsfError> {
        if !READONLY_METHODS.contains(&method) {
            return Err(MsfError::ReplayForbidden(method.to_owned()));
        }
        match self.call_once(method, args) {
            Ok(value) => Ok(value),
            Err(MsfError::Authentication) => {
                self.login()?;
                self.reauth_count = self.reauth_count.saturating_add(1);
                self.readonly_replay_count = self.readonly_replay_count.saturating_add(1);
                self.call_once(method, args)
            }
            Err(error) => Err(error),
        }
    }

    pub fn call_execution(&mut self, method: &str, args: &[Value]) -> Result<Value, MsfError> {
        self.call_once(method, args)
    }

    fn call_once(&mut self, method: &str, args: &[Value]) -> Result<Value, MsfError> {
        let token = self.token.as_ref().ok_or(MsfError::Authentication)?;
        let mut arguments = Vec::with_capacity(args.len() + 2);
        arguments.push(Value::from(method));
        arguments.push(Value::from(token.as_str()));
        arguments.extend_from_slice(args);
        self.transport.invoke(&arguments)
    }

    pub fn framework_version(&mut self) -> Result<FrameworkVersion, MsfError> {
        let value = self.call_readonly("core.version", &[])?;
        let values = map(&value)?;
        Ok(FrameworkVersion {
            version: string_value(values.get("version"))
                .unwrap_or_default()
                .to_owned(),
            ruby: string_value(values.get("ruby"))
                .unwrap_or_default()
                .to_owned(),
            api: string_value(values.get("api"))
                .unwrap_or_default()
                .to_owned(),
        })
    }

    pub fn ensure_workspace(&mut self, workspace: &str) -> Result<(), MsfError> {
        if workspace.is_empty()
            || workspace.len() > 128
            || !workspace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(MsfError::InvalidData);
        }

        let value = self.call_readonly("db.workspaces", &[])?;
        let values = map(&value)?;
        let workspaces = values
            .get("workspaces")
            .and_then(Value::as_array)
            .ok_or(MsfError::InvalidData)?;
        let exists = workspaces.iter().try_fold(false, |exists, item| {
            let item = map(item)?;
            Ok::<_, MsfError>(
                exists || string_value(item.get("name")).is_some_and(|name| name == workspace),
            )
        })?;

        if !exists {
            require_success(&self.call_execution("db.add_workspace", &[Value::from(workspace)])?)?;
        }
        require_success(&self.call_execution("db.set_workspace", &[Value::from(workspace)])?)
    }

    pub fn search_modules(&mut self, query: &str) -> Result<Vec<ModuleSummary>, MsfError> {
        if query.len() > 512 {
            return Err(MsfError::InvalidData);
        }
        let value = self.call_readonly("module.search", &[Value::from(query)])?;
        let items = value.as_array().ok_or(MsfError::InvalidData)?;
        items.iter().map(module_summary).collect()
    }

    pub fn module_options(
        &mut self,
        module_type: &str,
        fullname: &str,
    ) -> Result<Vec<ModuleOption>, MsfError> {
        validate_module_identity(module_type, fullname)?;
        let value = self.call_readonly(
            "module.options",
            &[Value::from(module_type), Value::from(fullname)],
        )?;
        let values = map(&value)?;
        values
            .iter()
            .map(|(name, value)| module_option(name, value))
            .collect()
    }

    pub fn execute_module(
        &mut self,
        module_type: &str,
        fullname: &str,
        options: &BTreeMap<String, serde_json::Value>,
    ) -> Result<ExecutionReceipt, MsfError> {
        validate_module_identity(module_type, fullname)?;
        let options = json_object_to_rmp(options)?;
        let value = self.call_execution(
            "module.execute",
            &[Value::from(module_type), Value::from(fullname), options],
        )?;
        let values = map(&value)?;
        Ok(ExecutionReceipt {
            job_id: string_value(values.get("job_id")).map(ToOwned::to_owned),
            uuid: string_value(values.get("uuid")).map(ToOwned::to_owned),
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

#[must_use]
pub fn redact_transcript(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_CONSOLE_READ_BYTES));
    for line in value.lines().take(4096) {
        let lowered = line.to_ascii_lowercase();
        if [
            "password",
            "passwd",
            "token",
            "authorization",
            "cookie",
            "secret",
        ]
        .iter()
        .any(|key| lowered.contains(key))
        {
            output.push_str("[REDACTED SENSITIVE LINE]\n");
        } else {
            output.push_str(line);
            output.push('\n');
        }
        if output.len() >= MAX_CONSOLE_READ_BYTES {
            output.truncate(MAX_CONSOLE_READ_BYTES);
            break;
        }
    }
    output
}

pub fn validate_module_identity(module_type: &str, fullname: &str) -> Result<(), MsfError> {
    let allowed_types = [
        "exploit",
        "auxiliary",
        "post",
        "payload",
        "encoder",
        "nop",
        "evasion",
    ];
    if !allowed_types.contains(&module_type)
        || fullname.is_empty()
        || fullname.len() > 512
        || fullname.starts_with('/')
        || fullname.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(MsfError::InvalidData);
    }
    Ok(())
}

fn module_summary(value: &Value) -> Result<ModuleSummary, MsfError> {
    let values = map(value)?;
    let module_type = string_value(values.get("type"))
        .unwrap_or_default()
        .to_owned();
    let fullname = string_value(values.get("fullname"))
        .unwrap_or_default()
        .to_owned();
    validate_module_identity(&module_type, &fullname)?;
    Ok(ModuleSummary {
        module_type,
        fullname,
        name: string_value(values.get("name"))
            .unwrap_or_default()
            .to_owned(),
        rank: string_value(values.get("rank"))
            .unwrap_or_default()
            .to_owned(),
        disclosure_date: string_value(values.get("disclosure_date")).map(ToOwned::to_owned),
        description: string_value(values.get("description"))
            .unwrap_or_default()
            .chars()
            .take(8192)
            .collect(),
    })
}

fn module_option(name: &str, value: &Value) -> Result<ModuleOption, MsfError> {
    let values = map(value)?;
    let default = values.get("default").map(value_to_json).transpose()?;
    let enums = values
        .get("enums")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| {
            items
                .iter()
                .filter_map(|item| value_as_str(item).map(ToOwned::to_owned))
                .take(1024)
                .collect()
        });
    Ok(ModuleOption {
        name: name.to_owned(),
        option_type: string_value(values.get("type"))
            .unwrap_or("string")
            .to_owned(),
        required: values
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        advanced: values
            .get("advanced")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        default,
        description: string_value(values.get("desc"))
            .unwrap_or_default()
            .chars()
            .take(4096)
            .collect(),
        enums,
    })
}

fn map(value: &Value) -> Result<BTreeMap<String, Value>, MsfError> {
    let entries = value.as_map().ok_or(MsfError::InvalidData)?;
    let mut output = BTreeMap::new();
    for (key, value) in entries {
        let key = value_as_str(key).ok_or(MsfError::InvalidData)?;
        output.insert(key.to_owned(), value.clone());
    }
    Ok(output)
}

fn string_value(value: Option<&Value>) -> Option<&str> {
    value.and_then(value_as_str)
}

fn require_success(value: &Value) -> Result<(), MsfError> {
    if string_value(map(value)?.get("result")) == Some("success") {
        Ok(())
    } else {
        Err(MsfError::InvalidData)
    }
}

#[must_use]
pub fn value_as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => value.as_str(),
        Value::Binary(value) => std::str::from_utf8(value).ok(),
        _ => None,
    }
}

fn json_object_to_rmp(values: &BTreeMap<String, serde_json::Value>) -> Result<Value, MsfError> {
    let entries = values
        .iter()
        .map(|(key, value)| Ok((Value::from(key.as_str()), json_to_rmp(value)?)))
        .collect::<Result<Vec<_>, MsfError>>()?;
    Ok(Value::Map(entries))
}

fn json_to_rmp(value: &serde_json::Value) -> Result<Value, MsfError> {
    Ok(match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(value) => Value::Boolean(*value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::from(value)
            } else if let Some(value) = value.as_u64() {
                Value::from(value)
            } else {
                Value::F64(value.as_f64().ok_or(MsfError::InvalidData)?)
            }
        }
        serde_json::Value::String(value) => Value::from(value.as_str()),
        serde_json::Value::Array(values) => Value::Array(
            values
                .iter()
                .map(json_to_rmp)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        serde_json::Value::Object(values) => Value::Map(
            values
                .iter()
                .map(|(key, value)| Ok((Value::from(key.as_str()), json_to_rmp(value)?)))
                .collect::<Result<Vec<_>, MsfError>>()?,
        ),
    })
}

pub fn value_to_json(value: &Value) -> Result<serde_json::Value, MsfError> {
    Ok(match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(value) => serde_json::Value::Bool(*value),
        Value::Integer(value) => {
            if let Some(value) = value.as_i64() {
                serde_json::json!(value)
            } else {
                serde_json::json!(value.as_u64().ok_or(MsfError::InvalidData)?)
            }
        }
        Value::F32(value) => serde_json::json!(value),
        Value::F64(value) => serde_json::json!(value),
        Value::String(value) => {
            serde_json::Value::String(value.as_str().ok_or(MsfError::InvalidData)?.to_owned())
        }
        Value::Binary(value) => {
            serde_json::Value::String(String::from_utf8_lossy(value).into_owned())
        }
        Value::Ext(_, _) => return Err(MsfError::InvalidData),
        Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(value_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Map(values) => {
            let mut output = serde_json::Map::new();
            for (key, value) in values {
                output.insert(
                    value_as_str(key).ok_or(MsfError::InvalidData)?.to_owned(),
                    value_to_json(value)?,
                );
            }
            serde_json::Value::Object(output)
        }
    })
}

fn read_bounded(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, MsfError> {
    let mut output = Vec::with_capacity(8192);
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if output.len().saturating_add(read) > limit {
                    return Err(MsfError::ResponseTooLarge);
                }
                output.extend_from_slice(&buffer[..read]);
                if expected_http_bytes(&output).is_some_and(|expected| output.len() >= expected) {
                    output.truncate(expected_http_bytes(&output).unwrap_or(output.len()));
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && expected_http_bytes(&output)
                    .is_some_and(|expected| output.len() >= expected) =>
            {
                break;
            }
            Err(_) => return Err(MsfError::Transport("read_response")),
        }
    }
    Ok(output)
}

fn expected_http_bytes(response: &[u8]) -> Option<usize> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&response[..header_end]).ok()?;
    let content_length = headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })?;
    (content_length <= MAX_RPC_RESPONSE_BYTES)
        .then(|| header_end.saturating_add(4).saturating_add(content_length))
}

fn parse_http_response(response: &[u8]) -> Result<(u16, &[u8]), MsfError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(MsfError::InvalidData)?;
    let headers =
        std::str::from_utf8(&response[..header_end]).map_err(|_| MsfError::InvalidData)?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(MsfError::InvalidData)?;
    let mut content_length = None;
    let mut seen = BTreeSet::new();
    for line in headers.lines().skip(1) {
        let (name, value) = line.split_once(':').ok_or(MsfError::InvalidData)?;
        let name = name.trim().to_ascii_lowercase();
        if !seen.insert(name.clone()) && name == "content-length" {
            return Err(MsfError::InvalidData);
        }
        if name == "content-length" {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| MsfError::InvalidData)?,
            );
        }
    }
    let payload = &response[header_end + 4..];
    if let Some(length) = content_length
        && (length != payload.len() || length > MAX_RPC_RESPONSE_BYTES)
    {
        return Err(MsfError::InvalidData);
    }
    Ok((status, payload))
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct MockTransport {
        responses: VecDeque<Result<Value, MsfError>>,
        calls: Vec<Vec<Value>>,
    }

    impl RpcTransport for MockTransport {
        fn invoke(&mut self, arguments: &[Value]) -> Result<Value, MsfError> {
            self.calls.push(arguments.to_vec());
            self.responses.pop_front().unwrap()
        }

        fn certificate_sha256(&self) -> Option<&str> {
            Some("00")
        }
    }

    fn success_map(entries: &[(&str, &str)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::from(*key), Value::from(*value)))
                .collect(),
        )
    }

    #[test]
    fn readonly_auth_expiry_replays_once() {
        let transport = MockTransport {
            responses: VecDeque::from([
                Ok(success_map(&[("result", "success"), ("token", "one")])),
                Err(MsfError::Authentication),
                Ok(success_map(&[("result", "success"), ("token", "two")])),
                Ok(success_map(&[("version", "6.4.135")])),
            ]),
            calls: Vec::new(),
        };
        let mut client = MsfRpcClient::new(transport, "user".into(), "x".repeat(32)).unwrap();
        client.login().unwrap();
        assert_eq!(client.framework_version().unwrap().version, "6.4.135");
        assert_eq!(client.reauth_count, 1);
        assert_eq!(client.readonly_replay_count, 1);
    }

    #[test]
    fn execution_auth_failure_is_never_replayed() {
        let transport = MockTransport {
            responses: VecDeque::from([
                Ok(success_map(&[("result", "success"), ("token", "one")])),
                Err(MsfError::Authentication),
            ]),
            calls: Vec::new(),
        };
        let mut client = MsfRpcClient::new(transport, "user".into(), "x".repeat(32)).unwrap();
        client.login().unwrap();
        assert!(matches!(
            client.execute_module("exploit", "test/example", &BTreeMap::new()),
            Err(MsfError::Authentication)
        ));
        assert_eq!(client.reauth_count, 0);
    }

    #[test]
    fn workspace_setup_reuses_existing_workspace() {
        let workspaces = Value::Map(vec![(
            Value::from("workspaces"),
            Value::Array(vec![Value::Map(vec![(
                Value::from("name"),
                Value::from("flagdeck_existing"),
            )])]),
        )]);
        let transport = MockTransport {
            responses: VecDeque::from([
                Ok(success_map(&[("result", "success"), ("token", "one")])),
                Ok(workspaces),
                Ok(success_map(&[("result", "success")])),
            ]),
            calls: Vec::new(),
        };
        let mut client = MsfRpcClient::new(transport, "user".into(), "x".repeat(32)).unwrap();
        client.login().unwrap();
        client.ensure_workspace("flagdeck_existing").unwrap();

        let methods: Vec<_> = client
            .transport
            .calls
            .iter()
            .filter_map(|call| call.first().and_then(value_as_str))
            .collect();
        assert_eq!(methods, ["auth.login", "db.workspaces", "db.set_workspace"]);
    }

    #[test]
    fn workspace_setup_creates_missing_workspace() {
        let workspaces = Value::Map(vec![(Value::from("workspaces"), Value::Array(Vec::new()))]);
        let transport = MockTransport {
            responses: VecDeque::from([
                Ok(success_map(&[("result", "success"), ("token", "one")])),
                Ok(workspaces),
                Ok(success_map(&[("result", "success")])),
                Ok(success_map(&[("result", "success")])),
            ]),
            calls: Vec::new(),
        };
        let mut client = MsfRpcClient::new(transport, "user".into(), "x".repeat(32)).unwrap();
        client.login().unwrap();
        client.ensure_workspace("flagdeck_new").unwrap();

        let methods: Vec<_> = client
            .transport
            .calls
            .iter()
            .filter_map(|call| call.first().and_then(value_as_str))
            .collect();
        assert_eq!(
            methods,
            [
                "auth.login",
                "db.workspaces",
                "db.add_workspace",
                "db.set_workspace"
            ]
        );
    }

    #[test]
    fn module_identity_and_transcript_are_bounded() {
        assert!(validate_module_identity("exploit", "linux/http/example").is_ok());
        assert!(validate_module_identity("exploit", "../escape").is_err());
        let redacted = redact_transcript("ok\nPASSWORD=hunter2\ntoken abc\nend");
        assert!(redacted.contains("ok"));
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("token abc"));
    }

    #[test]
    fn http_parser_enforces_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(parse_http_response(response).unwrap(), (200, &b"abc"[..]));
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc").is_err());
    }

    #[test]
    #[ignore = "requires an active local msfrpcd endpoint"]
    fn real_tls_pin_gate() {
        let port = std::env::var("FLAGDECK_R5_RPC_PORT")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let transport =
            HttpsMessagePackTransport::connect("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        assert_eq!(transport.certificate_sha256().map(str::len), Some(64));
    }

    #[test]
    #[ignore = "requires an active owned local msfrpcd endpoint"]
    fn real_same_uid_login_gate() {
        let pid = std::env::var("FLAGDECK_R5_RPC_PID").unwrap();
        let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
        let mut username = None;
        let mut password = None;
        for item in environ.split(|byte| *byte == 0) {
            if let Some(value) = item.strip_prefix(b"MSF_RPC_USER=") {
                username = Some(String::from_utf8(value.to_vec()).unwrap());
            }
            if let Some(value) = item.strip_prefix(b"MSF_RPC_PASS=") {
                password = Some(String::from_utf8(value.to_vec()).unwrap());
            }
        }
        let port = std::env::var("FLAGDECK_R5_RPC_PORT")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let transport =
            HttpsMessagePackTransport::connect("127.0.0.1", port, Duration::from_secs(5)).unwrap();
        let mut client =
            MsfRpcClient::new(transport, username.unwrap(), password.unwrap()).unwrap();
        client.login().unwrap();
        assert!(
            client
                .framework_version()
                .unwrap()
                .version
                .starts_with("6.4")
        );
        client
            .call_execution("db.set_workspace", &[Value::from("default")])
            .unwrap();
        client.logout().unwrap();
    }
}
