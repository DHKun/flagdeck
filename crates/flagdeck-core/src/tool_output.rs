//! 工具输出解析：把命令行工具产出的原始字节转换成结构化行。
//!
//! 这是一个深模块。对外只暴露三样东西：判定结果种类的 [`structured_result_kind`]、
//! 占位列头 [`http_discovery_columns`]，以及一次拿到列头与行的 [`parse_http_discovery`]。
//! 适配器的选择（[`HttpDiscoveryAdapter`]、[`select_http_discovery_adapter`]）和每种格式的
//! 解析器都留在模块内部。接入一种新工具输出格式只改这一个文件，调用方不再匹配适配器枚举。

use std::collections::BTreeMap;

use flagdeck_domain::{JobId, ToolIoKind, ToolRunIo};

use crate::{CoreError, StructuredResultColumnDto, StructuredResultKind, StructuredResultRowDto};

/// 一次 HTTP 发现解析的产物：列头总是可用，行可能解析失败。
pub(crate) struct HttpDiscoveryParse {
    pub columns: Vec<StructuredResultColumnDto>,
    pub rows: Result<Vec<StructuredResultRowDto>, CoreError>,
}

/// 选定适配器后，一次算出列头与行。调用方无需知道 [`HttpDiscoveryAdapter`]。
pub(crate) fn parse_http_discovery(
    parser_id: Option<&str>,
    tool_id: &str,
    logical_name: Option<&str>,
    bytes: &[u8],
) -> HttpDiscoveryParse {
    let adapter = select_http_discovery_adapter(parser_id, tool_id, logical_name);
    let columns = adapter_columns(adapter);
    let rows = match adapter {
        HttpDiscoveryAdapter::FfufJson | HttpDiscoveryAdapter::GenericJson => {
            parse_ffuf_structured_rows(bytes)
        }
        HttpDiscoveryAdapter::GobusterText => parse_gobuster_structured_rows(bytes),
        HttpDiscoveryAdapter::ArjunJson => parse_arjun_structured_rows(bytes),
        HttpDiscoveryAdapter::CurlHeaders => parse_curl_headers_structured_rows(bytes),
        HttpDiscoveryAdapter::Wafw00fJson => parse_wafw00f_structured_rows(bytes),
        HttpDiscoveryAdapter::DdddJsonl => parse_dddd_structured_rows(bytes),
        HttpDiscoveryAdapter::FscanJson => parse_fscan_structured_rows(bytes),
        HttpDiscoveryAdapter::SqlmapText => parse_sqlmap_structured_rows(bytes),
    };
    HttpDiscoveryParse { columns, rows }
}

fn adapter_columns(adapter: HttpDiscoveryAdapter) -> Vec<StructuredResultColumnDto> {
    match adapter {
        HttpDiscoveryAdapter::ArjunJson => arjun_result_columns(),
        HttpDiscoveryAdapter::Wafw00fJson => wafw00f_result_columns(),
        HttpDiscoveryAdapter::CurlHeaders => curl_result_columns(),
        HttpDiscoveryAdapter::DdddJsonl | HttpDiscoveryAdapter::FscanJson => {
            host_service_result_columns()
        }
        HttpDiscoveryAdapter::SqlmapText => sqlmap_result_columns(),
        _ => http_discovery_columns(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpDiscoveryAdapter {
    FfufJson,
    GobusterText,
    ArjunJson,
    CurlHeaders,
    Wafw00fJson,
    DdddJsonl,
    FscanJson,
    SqlmapText,
    GenericJson,
}

pub(crate) fn structured_result_kind(
    io: &ToolRunIo,
    parser_id: Option<&str>,
    tool_id: &str,
) -> StructuredResultKind {
    if matches!(
        select_http_discovery_adapter(parser_id, tool_id, None),
        HttpDiscoveryAdapter::FfufJson
            | HttpDiscoveryAdapter::GobusterText
            | HttpDiscoveryAdapter::ArjunJson
            | HttpDiscoveryAdapter::CurlHeaders
            | HttpDiscoveryAdapter::Wafw00fJson
            | HttpDiscoveryAdapter::DdddJsonl
            | HttpDiscoveryAdapter::FscanJson
            | HttpDiscoveryAdapter::SqlmapText
    ) || io
        .outputs
        .iter()
        .any(|output| output.kind == ToolIoKind::HttpDiscovery)
    {
        StructuredResultKind::HttpDiscovery
    } else if io
        .outputs
        .iter()
        .any(|output| output.kind == ToolIoKind::RawArtifact)
    {
        StructuredResultKind::RawOnly
    } else {
        StructuredResultKind::Unknown
    }
}

fn select_http_discovery_adapter(
    parser_id: Option<&str>,
    _tool_id: &str,
    logical_name: Option<&str>,
) -> HttpDiscoveryAdapter {
    if let Some(id) = parser_id {
        if id == "flagdeck.ffuf-json" || id.ends_with(".ffuf-json") || id.contains("ffuf") {
            return HttpDiscoveryAdapter::FfufJson;
        }
        if id == "flagdeck.gobuster-text"
            || id.ends_with(".gobuster-text")
            || id.contains("gobuster")
        {
            return HttpDiscoveryAdapter::GobusterText;
        }
        if id == "flagdeck.arjun-json" || id.ends_with(".arjun-json") || id.contains("arjun") {
            return HttpDiscoveryAdapter::ArjunJson;
        }
        if id == "flagdeck.curl-headers" || id.ends_with(".curl-headers") || id.contains("curl") {
            return HttpDiscoveryAdapter::CurlHeaders;
        }
        if id == "flagdeck.wafw00f-json" || id.ends_with(".wafw00f-json") || id.contains("wafw00f")
        {
            return HttpDiscoveryAdapter::Wafw00fJson;
        }
        if id == "flagdeck.dddd-jsonl" || id.ends_with(".dddd-jsonl") || id.contains("dddd") {
            return HttpDiscoveryAdapter::DdddJsonl;
        }
        if id == "flagdeck.fscan-json" || id.ends_with(".fscan-json") || id.contains("fscan") {
            return HttpDiscoveryAdapter::FscanJson;
        }
        if id == "flagdeck.sqlmap-text" || id.ends_with(".sqlmap-text") || id.contains("sqlmap") {
            return HttpDiscoveryAdapter::SqlmapText;
        }
    }
    if logical_name.is_some_and(|name| name.contains("gobuster")) {
        return HttpDiscoveryAdapter::GobusterText;
    }
    if logical_name.is_some_and(|name| name.contains("arjun")) {
        return HttpDiscoveryAdapter::ArjunJson;
    }
    if logical_name.is_some_and(|name| name.contains("headers") || name.contains("curl")) {
        return HttpDiscoveryAdapter::CurlHeaders;
    }
    if logical_name.is_some_and(|name| name.contains("wafw00f")) {
        return HttpDiscoveryAdapter::Wafw00fJson;
    }
    if logical_name.is_some_and(|name| name.contains("dddd")) {
        return HttpDiscoveryAdapter::DdddJsonl;
    }
    if logical_name.is_some_and(|name| name.contains("fscan")) {
        return HttpDiscoveryAdapter::FscanJson;
    }
    if logical_name.is_some_and(|name| name.contains("ffuf")) {
        return HttpDiscoveryAdapter::FfufJson;
    }
    if logical_name.is_some_and(|name| name.contains("sqlmap")) {
        return HttpDiscoveryAdapter::SqlmapText;
    }
    HttpDiscoveryAdapter::GenericJson
}

pub(crate) fn http_discovery_columns() -> Vec<StructuredResultColumnDto> {
    vec![
        StructuredResultColumnDto {
            key: "url".to_owned(),
            label: "URL".to_owned(),
        },
        StructuredResultColumnDto {
            key: "path".to_owned(),
            label: "路径".to_owned(),
        },
        StructuredResultColumnDto {
            key: "status".to_owned(),
            label: "状态".to_owned(),
        },
        StructuredResultColumnDto {
            key: "length".to_owned(),
            label: "长度".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_job".to_owned(),
            label: "来源任务".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_artifact".to_owned(),
            label: "来源证据".to_owned(),
        },
    ]
}

fn parse_ffuf_structured_rows(bytes: &[u8]) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let records = if let Some(results) = value.get("results").and_then(|item| item.as_array()) {
        results.clone()
    } else if let Some(results) = value.as_array() {
        results.clone()
    } else {
        return Err(CoreError::InvalidRequest);
    };
    let mut rows = Vec::new();
    for (index, record) in records.into_iter().enumerate() {
        let url = record
            .get("url")
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let path = record
            .get("input")
            .and_then(|item| item.get("FUZZ"))
            .and_then(|item| item.as_str())
            .map(str::to_owned)
            .or_else(|| {
                url::Url::parse(&url)
                    .ok()
                    .map(|parsed| parsed.path().to_owned())
            })
            .unwrap_or_default();
        let status = record
            .get("status")
            .map(|item| match item {
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::String(text) => text.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let length = record
            .get("length")
            .map(|item| match item {
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::String(text) => text.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let mut cells = BTreeMap::new();
        cells.insert("url".to_owned(), url);
        cells.insert("path".to_owned(), path);
        cells.insert("status".to_owned(), status);
        cells.insert("length".to_owned(), length);
        cells.insert("source_job".to_owned(), String::new());
        cells.insert("source_artifact".to_owned(), String::new());
        rows.push(StructuredResultRowDto {
            result_id: format!("row:{index}"),
            cells,
            source_job_id: JobId::new(),
            source_artifact_id: None,
        });
    }
    Ok(rows)
}

fn arjun_result_columns() -> Vec<StructuredResultColumnDto> {
    vec![
        StructuredResultColumnDto {
            key: "url".to_owned(),
            label: "URL".to_owned(),
        },
        StructuredResultColumnDto {
            key: "param".to_owned(),
            label: "参数".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_job".to_owned(),
            label: "来源任务".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_artifact".to_owned(),
            label: "来源证据".to_owned(),
        },
    ]
}

fn parse_gobuster_structured_rows(bytes: &[u8]) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('=')
            || trimmed.starts_with("Gobuster")
            || trimmed.starts_with('[')
        {
            continue;
        }
        // e.g. /admin              (Status: 200) [Size: 14]
        let Some(captures) = regex_lite_gobuster_line(trimmed) else {
            continue;
        };
        let mut cells = BTreeMap::new();
        cells.insert("path".to_owned(), captures.0);
        cells.insert("status".to_owned(), captures.1);
        cells.insert("length".to_owned(), captures.2);
        cells.insert("url".to_owned(), String::new());
        cells.insert("source_job".to_owned(), String::new());
        cells.insert("source_artifact".to_owned(), String::new());
        rows.push(StructuredResultRowDto {
            result_id: format!("row:{index}"),
            cells,
            source_job_id: JobId::new(),
            source_artifact_id: None,
        });
    }
    if rows.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    Ok(rows)
}

fn regex_lite_gobuster_line(line: &str) -> Option<(String, String, String)> {
    let path_end = line.find(" (Status:")?;
    let path = line[..path_end].trim().to_owned();
    let after = &line[path_end + " (Status:".len()..];
    let status_end = after.find(')')?;
    let status = after[..status_end].trim().to_owned();
    let length = after
        .find("[Size:")
        .and_then(|start| {
            let rest = &after[start + "[Size:".len()..];
            rest.find(']').map(|end| rest[..end].trim().to_owned())
        })
        .unwrap_or_default();
    Some((path, status, length))
}

fn curl_result_columns() -> Vec<StructuredResultColumnDto> {
    vec![
        StructuredResultColumnDto {
            key: "status".to_owned(),
            label: "状态".to_owned(),
        },
        StructuredResultColumnDto {
            key: "url".to_owned(),
            label: "URL".to_owned(),
        },
        StructuredResultColumnDto {
            key: "content_type".to_owned(),
            label: "类型".to_owned(),
        },
        StructuredResultColumnDto {
            key: "length".to_owned(),
            label: "长度".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_job".to_owned(),
            label: "来源任务".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_artifact".to_owned(),
            label: "来源证据".to_owned(),
        },
    ]
}

fn wafw00f_result_columns() -> Vec<StructuredResultColumnDto> {
    vec![
        StructuredResultColumnDto {
            key: "url".to_owned(),
            label: "URL".to_owned(),
        },
        StructuredResultColumnDto {
            key: "detected".to_owned(),
            label: "检出".to_owned(),
        },
        StructuredResultColumnDto {
            key: "firewall".to_owned(),
            label: "WAF".to_owned(),
        },
        StructuredResultColumnDto {
            key: "manufacturer".to_owned(),
            label: "厂商".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_job".to_owned(),
            label: "来源任务".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_artifact".to_owned(),
            label: "来源证据".to_owned(),
        },
    ]
}

fn parse_curl_headers_structured_rows(
    bytes: &[u8],
) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let mut status = String::new();
    let mut content_type = String::new();
    let mut length = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.to_ascii_uppercase().starts_with("HTTP/") {
            // HTTP/1.1 200 OK
            let parts: Vec<_> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                parts[1].clone_into(&mut status);
            }
            continue;
        }
        if let Some(value) = trimmed
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.trim().to_owned())
        {
            content_type = value;
        }
        if let Some(value) = trimmed
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().to_owned())
        {
            length = value;
        }
    }
    if status.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    let mut cells = BTreeMap::new();
    cells.insert("status".to_owned(), status);
    cells.insert("url".to_owned(), String::new());
    cells.insert("content_type".to_owned(), content_type);
    cells.insert("length".to_owned(), length);
    cells.insert("source_job".to_owned(), String::new());
    cells.insert("source_artifact".to_owned(), String::new());
    Ok(vec![StructuredResultRowDto {
        result_id: "row:0".to_owned(),
        cells,
        source_job_id: JobId::new(),
        source_artifact_id: None,
    }])
}

fn host_service_result_columns() -> Vec<StructuredResultColumnDto> {
    vec![
        StructuredResultColumnDto {
            key: "host".to_owned(),
            label: "主机".to_owned(),
        },
        StructuredResultColumnDto {
            key: "port".to_owned(),
            label: "端口".to_owned(),
        },
        StructuredResultColumnDto {
            key: "service".to_owned(),
            label: "服务".to_owned(),
        },
        StructuredResultColumnDto {
            key: "url".to_owned(),
            label: "URL".to_owned(),
        },
        StructuredResultColumnDto {
            key: "status".to_owned(),
            label: "状态".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_job".to_owned(),
            label: "来源任务".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_artifact".to_owned(),
            label: "来源证据".to_owned(),
        },
    ]
}

fn parse_dddd_structured_rows(bytes: &[u8]) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|_| CoreError::InvalidRequest)?;
        let url = value
            .get("uri")
            .or_else(|| value.get("url"))
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let host = value
            .get("ip")
            .or_else(|| value.get("host"))
            .and_then(|item| item.as_str())
            .map(str::to_owned)
            .or_else(|| {
                url::Url::parse(&url)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(str::to_owned))
            })
            .unwrap_or_default();
        let port = value
            .get("port")
            .map(|item| match item {
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::String(text) => text.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let service = value
            .get("type")
            .or_else(|| value.get("service"))
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let status = value
            .pointer("/web/status")
            .or_else(|| value.get("status"))
            .map(|item| match item {
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::String(text) => text.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let mut cells = BTreeMap::new();
        cells.insert("host".to_owned(), host);
        cells.insert("port".to_owned(), port);
        cells.insert("service".to_owned(), service);
        cells.insert("url".to_owned(), url);
        cells.insert("status".to_owned(), status);
        cells.insert("source_job".to_owned(), String::new());
        cells.insert("source_artifact".to_owned(), String::new());
        rows.push(StructuredResultRowDto {
            result_id: format!("row:{index}"),
            cells,
            source_job_id: JobId::new(),
            source_artifact_id: None,
        });
    }
    if rows.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    Ok(rows)
}

fn parse_fscan_structured_rows(bytes: &[u8]) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let records = if let Some(array) = value.as_array() {
        array.clone()
    } else if value.is_object() {
        vec![value]
    } else {
        return Err(CoreError::InvalidRequest);
    };
    let mut rows = Vec::new();
    for (index, record) in records.into_iter().enumerate() {
        let host = record
            .get("host")
            .or_else(|| record.get("ip"))
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let port = record
            .get("port")
            .map(|item| match item {
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::String(text) => text.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let service = record
            .get("service")
            .or_else(|| record.get("protocol"))
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let url = record
            .get("url")
            .and_then(|item| item.as_str())
            .map_or_else(
                || {
                    if !host.is_empty() && !port.is_empty() {
                        format!("http://{host}:{port}/")
                    } else {
                        String::new()
                    }
                },
                str::to_owned,
            );
        let status = record
            .get("info")
            .or_else(|| record.get("status"))
            .map(|item| match item {
                serde_json::Value::String(text) => text.clone(),
                serde_json::Value::Number(number) => number.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let mut cells = BTreeMap::new();
        cells.insert("host".to_owned(), host);
        cells.insert("port".to_owned(), port);
        cells.insert("service".to_owned(), service);
        cells.insert("url".to_owned(), url);
        cells.insert("status".to_owned(), status);
        cells.insert("source_job".to_owned(), String::new());
        cells.insert("source_artifact".to_owned(), String::new());
        rows.push(StructuredResultRowDto {
            result_id: format!("row:{index}"),
            cells,
            source_job_id: JobId::new(),
            source_artifact_id: None,
        });
    }
    if rows.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    Ok(rows)
}

fn parse_wafw00f_structured_rows(bytes: &[u8]) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let records = if let Some(array) = value.as_array() {
        array.clone()
    } else if value.is_object() {
        vec![value]
    } else {
        return Err(CoreError::InvalidRequest);
    };
    let mut rows = Vec::new();
    for (index, record) in records.into_iter().enumerate() {
        let url = record
            .get("url")
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let detected = record
            .get("detected")
            .map(|item| match item {
                serde_json::Value::Bool(flag) => flag.to_string(),
                serde_json::Value::String(text) => text.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let firewall = record
            .get("firewall")
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let manufacturer = record
            .get("manufacturer")
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let mut cells = BTreeMap::new();
        cells.insert("url".to_owned(), url);
        cells.insert("detected".to_owned(), detected);
        cells.insert("firewall".to_owned(), firewall);
        cells.insert("manufacturer".to_owned(), manufacturer);
        cells.insert("source_job".to_owned(), String::new());
        cells.insert("source_artifact".to_owned(), String::new());
        rows.push(StructuredResultRowDto {
            result_id: format!("row:{index}"),
            cells,
            source_job_id: JobId::new(),
            source_artifact_id: None,
        });
    }
    if rows.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    Ok(rows)
}

fn parse_arjun_structured_rows(bytes: &[u8]) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let object = value.as_object().ok_or(CoreError::InvalidRequest)?;
    let mut rows = Vec::new();
    let mut index = 0_usize;
    for (url, params) in object {
        if url == "headers" || url == "method" {
            continue;
        }
        let param_list = if let Some(map) = params.as_object() {
            // Shape: { "http://x": { "params": ["a","b"] } } or nested values
            if let Some(list) = map.get("params").and_then(|item| item.as_array()) {
                list.iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            } else {
                map.keys().cloned().collect()
            }
        } else if let Some(list) = params.as_array() {
            list.iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        } else if let Some(text) = params.as_str() {
            vec![text.to_owned()]
        } else {
            continue;
        };
        for param in param_list {
            let mut cells = BTreeMap::new();
            cells.insert("url".to_owned(), url.clone());
            cells.insert("param".to_owned(), param);
            cells.insert("source_job".to_owned(), String::new());
            cells.insert("source_artifact".to_owned(), String::new());
            rows.push(StructuredResultRowDto {
                result_id: format!("row:{index}"),
                cells,
                source_job_id: JobId::new(),
                source_artifact_id: None,
            });
            index += 1;
        }
    }
    if rows.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    Ok(rows)
}

fn sqlmap_result_columns() -> Vec<StructuredResultColumnDto> {
    vec![
        StructuredResultColumnDto {
            key: "parameter".to_owned(),
            label: "参数".to_owned(),
        },
        StructuredResultColumnDto {
            key: "technique".to_owned(),
            label: "技术".to_owned(),
        },
        StructuredResultColumnDto {
            key: "title".to_owned(),
            label: "发现".to_owned(),
        },
        StructuredResultColumnDto {
            key: "payload".to_owned(),
            label: "Payload".to_owned(),
        },
        StructuredResultColumnDto {
            key: "dbms".to_owned(),
            label: "DBMS".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_job".to_owned(),
            label: "来源任务".to_owned(),
        },
        StructuredResultColumnDto {
            key: "source_artifact".to_owned(),
            label: "来源证据".to_owned(),
        },
    ]
}

fn parse_sqlmap_structured_rows(bytes: &[u8]) -> Result<Vec<StructuredResultRowDto>, CoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::InvalidRequest)?;
    let mut dbms = String::new();
    let mut current_parameter = String::new();
    let mut current_technique = String::new();
    let mut current_title = String::new();
    let mut rows = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("back-end DBMS:") {
            value.trim().clone_into(&mut dbms);
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("Parameter:") {
            value.trim().clone_into(&mut current_parameter);
            current_technique.clear();
            current_title.clear();
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("Type:") {
            value.trim().clone_into(&mut current_technique);
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("Title:") {
            value.trim().clone_into(&mut current_title);
            continue;
        }
        let Some(payload) = trimmed.strip_prefix("Payload:") else {
            continue;
        };
        let payload = payload.trim();
        if current_parameter.is_empty()
            || current_technique.is_empty()
            || current_title.is_empty()
            || payload.is_empty()
        {
            continue;
        }
        let mut cells = BTreeMap::new();
        cells.insert("parameter".to_owned(), current_parameter.clone());
        cells.insert("technique".to_owned(), current_technique.clone());
        cells.insert("title".to_owned(), current_title.clone());
        cells.insert("payload".to_owned(), payload.to_owned());
        cells.insert("dbms".to_owned(), dbms.clone());
        cells.insert("source_job".to_owned(), String::new());
        cells.insert("source_artifact".to_owned(), String::new());
        rows.push(StructuredResultRowDto {
            result_id: format!("row:{}", rows.len()),
            cells,
            source_job_id: JobId::new(),
            source_artifact_id: None,
        });
        current_technique.clear();
        current_title.clear();
    }
    if rows.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    for row in &mut rows {
        if row.cells.get("dbms").is_some_and(String::is_empty) {
            row.cells.insert("dbms".to_owned(), dbms.clone());
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_result_adapter_is_selected_by_parser_id() {
        assert!(matches!(
            select_http_discovery_adapter(
                Some("flagdeck.ffuf-json"),
                "renamed-content-discovery",
                None
            ),
            HttpDiscoveryAdapter::FfufJson
        ));
        assert!(matches!(
            select_http_discovery_adapter(None, "ffuf", None),
            HttpDiscoveryAdapter::GenericJson
        ));
    }

    #[test]
    fn logical_name_selects_adapter_when_parser_id_absent() {
        assert!(matches!(
            select_http_discovery_adapter(None, "any", Some("gobuster-output.txt")),
            HttpDiscoveryAdapter::GobusterText
        ));
        assert!(matches!(
            select_http_discovery_adapter(None, "any", Some("dddd-output.jsonl")),
            HttpDiscoveryAdapter::DdddJsonl
        ));
    }

    #[test]
    fn ffuf_json_parses_directly_from_bytes() {
        let bytes = br#"{"results":[{"url":"http://t/admin","status":200,"length":14,
            "input":{"FUZZ":"admin"}}]}"#;
        let rows = parse_ffuf_structured_rows(bytes).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cells.get("path").map(String::as_str), Some("admin"));
        assert_eq!(rows[0].cells.get("status").map(String::as_str), Some("200"));
    }

    #[test]
    fn gobuster_text_parses_directly_from_bytes() {
        let bytes =
            b"/admin              (Status: 200) [Size: 14]\n/secret (Status: 403) [Size: 9]\n";
        let rows = parse_gobuster_structured_rows(bytes).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].cells.get("path").map(String::as_str),
            Some("/admin")
        );
        assert_eq!(rows[0].cells.get("length").map(String::as_str), Some("14"));
    }

    #[test]
    fn empty_gobuster_output_is_a_parse_error() {
        assert!(matches!(
            parse_gobuster_structured_rows(b"=== nothing here ===\n"),
            Err(CoreError::InvalidRequest)
        ));
    }

    #[test]
    fn parse_http_discovery_returns_columns_even_when_rows_fail() {
        let parsed = parse_http_discovery(Some("flagdeck.gobuster-text"), "gobuster", None, b"");
        assert!(parsed.rows.is_err());
        assert!(!parsed.columns.is_empty());
    }

    #[test]
    fn sqlmap_text_extracts_injection_findings() {
        let bytes = br"
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE clause
    Payload: id=1 AND 1=1
back-end DBMS: MySQL
";
        let rows = parse_sqlmap_structured_rows(bytes).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].cells.get("parameter").map(String::as_str),
            Some("id (GET)")
        );
        assert_eq!(rows[0].cells.get("dbms").map(String::as_str), Some("MySQL"));
    }

    #[test]
    fn sqlmap_text_rejects_payload_without_finding_context() {
        assert!(matches!(
            parse_sqlmap_structured_rows(b"warning: request failed\nPayload: diagnostic text\n"),
            Err(CoreError::InvalidRequest)
        ));
    }

    #[test]
    fn sqlmap_text_does_not_reuse_completed_finding_context() {
        let bytes = br"
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE clause
    Payload: id=1 AND 1=1
    Payload: unrelated diagnostic text
";
        let rows = parse_sqlmap_structured_rows(bytes).unwrap();
        assert_eq!(rows.len(), 1);
    }
}
