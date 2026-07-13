#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;

use flagdeck_domain::{ADAPTER_PROTOCOL, MAX_CONTROL_FRAME_BYTES, ProjectId, RiskLevel};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("control frame exceeds one MiB")]
    FrameTooLarge,
    #[error("zero-length control frame")]
    EmptyFrame,
    #[error("invalid UTF-8 or JSON control frame")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported adapter protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("missing request metadata")]
    MissingMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestMetadata {
    pub core_job_id: String,
    pub adapter_job_id: Option<String>,
    pub idempotency_key: String,
    pub deadline_unix_millis: String,
}

impl RequestMetadata {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.core_job_id.is_empty()
            || self.idempotency_key.is_empty()
            || self.adapter_job_id.as_ref().is_some_and(String::is_empty)
            || self
                .deadline_unix_millis
                .parse::<u64>()
                .ok()
                .is_none_or(|value| value == 0)
        {
            return Err(ProtocolError::MissingMetadata);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub metadata: RequestMetadata,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub sequence: u64,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: String,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub redacted_data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeParams {
    pub protocol: String,
    pub project_id: ProjectId,
    pub capabilities: Vec<String>,
    pub permissions: AdapterPermissions,
}

impl InitializeParams {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != ADAPTER_PROTOCOL {
            return Err(ProtocolError::UnsupportedProtocol(self.protocol.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPermissions {
    pub network: Vec<String>,
    pub project_artifacts: String,
    pub secrets: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterDescription {
    pub adapter_id: String,
    pub adapter_version: String,
    pub protocol: String,
    pub methods: Vec<String>,
    pub risk_level: RiskLevel,
    pub input_schema_sha256: String,
    pub output_schema_sha256: String,
    pub ui_schema_sha256: String,
    pub capabilities: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    expected: Option<usize>,
}

impl FrameDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
            expected: None,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Value>, ProtocolError> {
        if self.buffer.len().saturating_add(chunk.len()) > MAX_CONTROL_FRAME_BYTES + 4 {
            return Err(ProtocolError::FrameTooLarge);
        }
        self.buffer.extend_from_slice(chunk);
        let mut messages = Vec::new();
        loop {
            if self.expected.is_none() {
                if self.buffer.len() < 4 {
                    break;
                }
                let length = u32::from_be_bytes([
                    self.buffer[0],
                    self.buffer[1],
                    self.buffer[2],
                    self.buffer[3],
                ]);
                let length = usize::try_from(length).map_err(|_| ProtocolError::FrameTooLarge)?;
                if length == 0 {
                    return Err(ProtocolError::EmptyFrame);
                }
                if length > MAX_CONTROL_FRAME_BYTES {
                    return Err(ProtocolError::FrameTooLarge);
                }
                self.buffer.drain(..4);
                self.expected = Some(length);
            }
            let Some(expected) = self.expected else {
                break;
            };
            if self.buffer.len() < expected {
                break;
            }
            let payload: Vec<u8> = self.buffer.drain(..expected).collect();
            messages.push(serde_json::from_slice(&payload)?);
            self.expected = None;
        }
        Ok(messages)
    }

    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(message)?;
    if payload.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[must_use]
pub fn standard_methods() -> [&'static str; 8] {
    [
        "initialize",
        "describe",
        "health",
        "prepare",
        "start",
        "cancel",
        "import_artifact",
        "shutdown",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            id: "request-1".to_owned(),
            method: "health".to_owned(),
            metadata: RequestMetadata {
                core_job_id: "core-job".to_owned(),
                adapter_job_id: None,
                idempotency_key: "idem".to_owned(),
                deadline_unix_millis: "1".to_owned(),
            },
            params: Value::Null,
        }
    }

    #[test]
    fn fragmented_and_coalesced_frames_decode_in_order() {
        let first = encode_frame(&request()).unwrap();
        let mut second_request = request();
        second_request.id = "request-2".to_owned();
        let second = encode_frame(&second_request).unwrap();
        let mut decoder = FrameDecoder::new();
        assert!(decoder.push(&first[..3]).unwrap().is_empty());
        let mut remainder = first[3..].to_vec();
        remainder.extend_from_slice(&second);
        let messages = decoder.push(&remainder).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["id"], "request-1");
        assert_eq!(messages[1]["id"], "request-2");
    }

    #[test]
    fn oversized_and_empty_frames_are_rejected() {
        let oversized = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1)
            .unwrap()
            .to_be_bytes();
        assert!(matches!(
            FrameDecoder::new().push(&oversized),
            Err(ProtocolError::FrameTooLarge)
        ));
        assert!(matches!(
            FrameDecoder::new().push(&0_u32.to_be_bytes()),
            Err(ProtocolError::EmptyFrame)
        ));
    }

    #[test]
    fn protocol_version_and_metadata_are_explicit() {
        let params = InitializeParams {
            protocol: ADAPTER_PROTOCOL.to_owned(),
            project_id: ProjectId::new(),
            capabilities: vec!["health".to_owned()],
            permissions: AdapterPermissions {
                network: Vec::new(),
                project_artifacts: "read-only".to_owned(),
                secrets: "none".to_owned(),
            },
        };
        assert!(params.validate().is_ok());
        let mut wrong = params;
        wrong.protocol = "flagdeck.adapter.v2".to_owned();
        assert!(wrong.validate().is_err());
        assert!(request().metadata.validate().is_ok());
    }

    #[test]
    fn shared_python_and_rust_fixture_obeys_the_frozen_contract() {
        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/r3/adapter-protocol/messages.json"
        )))
        .unwrap();
        assert_eq!(fixture["protocol"], flagdeck_domain::ADAPTER_PROTOCOL);
        let typed: JsonRpcRequest = serde_json::from_value(fixture["request"].clone()).unwrap();
        assert_eq!(typed.method, "health");
        let frame = encode_frame(&typed).unwrap();
        let mut decoder = FrameDecoder::new();
        let messages = decoder.push(&frame).unwrap();
        assert_eq!(messages, vec![fixture["request"].clone()]);
        assert!(
            serde_json::from_value::<JsonRpcRequest>(fixture["invalid_unknown_request"].clone())
                .is_err()
        );
    }
}
