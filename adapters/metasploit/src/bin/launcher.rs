use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use nix::unistd::execve;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"FDM1";
const MAX_CREDENTIAL_BYTES: usize = 1024;
const MSFRPCD: &str = "/opt/metasploit-framework/embedded/framework/msfrpcd";
const EMBEDDED_PATH: &str = "/opt/metasploit-framework/embedded/bin:/usr/bin:/bin";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    DirectSocket,
    SystemdCredential,
}

#[derive(Debug)]
struct Args {
    channel: Channel,
    source: OsString,
    home: PathBuf,
    config_root: PathBuf,
    port: u16,
    token_timeout: u16,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Metasploit credential launcher failed: {error:#}");
            ExitCode::from(70)
        }
    }
}

fn run() -> Result<()> {
    let config = parse_args(env::args_os().skip(1))?;
    validate_runtime_paths(&config)?;
    let mut credential = read_credential(&config)?;
    let (user_range, password_range) = parse_credential(&credential)?;
    let user_env = make_secret_env(b"MSF_RPC_USER=", &credential[user_range])?;
    let password_env = make_secret_env(b"MSF_RPC_PASS=", &credential[password_range])?;
    credential.zeroize();
    drop(credential);

    let target = CString::new(MSFRPCD)?;
    let argv = build_argv(&config)?;
    let environment = build_environment(&config, user_env, password_env)?;
    let argv_refs: Vec<&CStr> = argv.iter().map(CString::as_c_str).collect();
    let environment_refs: Vec<&CStr> = environment.iter().map(CString::as_c_str).collect();
    execve(&target, &argv_refs, &environment_refs).context("execve msfrpcd failed")?;
    Ok(())
}

fn parse_args(arguments: impl Iterator<Item = OsString>) -> Result<Args> {
    let mut channel = None;
    let mut source = None;
    let mut home = None;
    let mut config_root = None;
    let mut port = None;
    let mut token_timeout = None;
    let mut items = arguments.peekable();
    while let Some(flag) = items.next() {
        let value = items
            .next()
            .with_context(|| format!("missing value for {}", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--channel") => {
                channel = Some(match value.to_str() {
                    Some("direct-socket") => Channel::DirectSocket,
                    Some("systemd-credential") => Channel::SystemdCredential,
                    _ => bail!("unsupported credential channel"),
                });
            }
            Some("--source") => source = Some(value),
            Some("--home") => home = Some(PathBuf::from(value)),
            Some("--config-root") => config_root = Some(PathBuf::from(value)),
            Some("--port") => port = Some(parse_u16(&value, "port")?),
            Some("--token-timeout") => {
                token_timeout = Some(parse_u16(&value, "token timeout")?);
            }
            _ => bail!("unknown launcher argument"),
        }
    }
    Ok(Args {
        channel: channel.context("--channel is required")?,
        source: source.context("--source is required")?,
        home: home.context("--home is required")?,
        config_root: config_root.context("--config-root is required")?,
        port: port.context("--port is required")?,
        token_timeout: token_timeout.context("--token-timeout is required")?,
    })
}

fn parse_u16(value: &OsStr, label: &str) -> Result<u16> {
    let parsed = value
        .to_str()
        .context("numeric argument is not UTF-8")?
        .parse::<u16>()
        .with_context(|| format!("invalid {label}"))?;
    ensure!(parsed > 0, "{label} must be positive");
    Ok(parsed)
}

fn validate_runtime_paths(args: &Args) -> Result<()> {
    ensure!(
        Path::new(MSFRPCD).is_file(),
        "locked msfrpcd path is unavailable"
    );
    ensure!(
        args.home.is_absolute() && args.home.is_dir(),
        "invalid HOME"
    );
    ensure!(
        args.config_root.is_absolute() && args.config_root.is_dir(),
        "invalid config root"
    );
    match args.channel {
        Channel::DirectSocket => {
            let source = Path::new(&args.source);
            ensure!(source.is_absolute(), "socket path must be absolute");
            ensure!(
                fs::symlink_metadata(source)?.file_type().is_socket(),
                "credential source is not a socket"
            );
        }
        Channel::SystemdCredential => validate_credential_id(&args.source)?,
    }
    Ok(())
}

fn validate_credential_id(value: &OsStr) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(
        !bytes.is_empty() && bytes.len() <= 64,
        "invalid credential ID length"
    );
    ensure!(
        bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        "invalid credential ID"
    );
    Ok(())
}

fn read_credential(args: &Args) -> Result<Zeroizing<Vec<u8>>> {
    let mut reader: Box<dyn Read> = match args.channel {
        Channel::DirectSocket => {
            let stream = UnixStream::connect(Path::new(&args.source))?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            Box::new(stream)
        }
        Channel::SystemdCredential => {
            let directory = env::var_os("CREDENTIALS_DIRECTORY")
                .context("CREDENTIALS_DIRECTORY is unavailable")?;
            let path = PathBuf::from(directory).join(&args.source);
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.file_type().is_file(),
                "credential is not a regular file"
            );
            ensure!(
                metadata.len() <= MAX_CREDENTIAL_BYTES as u64,
                "credential is oversized"
            );
            Box::new(File::open(path)?)
        }
    };
    let mut data = Zeroizing::new(Vec::with_capacity(128));
    reader
        .by_ref()
        .take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() <= MAX_CREDENTIAL_BYTES,
        "credential is oversized"
    );
    Ok(data)
}

fn parse_credential(data: &[u8]) -> Result<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    ensure!(
        data.len() >= 8 && &data[..4] == MAGIC,
        "invalid credential magic"
    );
    let user_length = usize::from(u16::from_be_bytes([data[4], data[5]]));
    let password_length = usize::from(u16::from_be_bytes([data[6], data[7]]));
    ensure!((1..=64).contains(&user_length), "invalid username length");
    ensure!(
        (32..=256).contains(&password_length),
        "invalid password length"
    );
    let password_start = 8 + user_length;
    let end = password_start + password_length;
    ensure!(data.len() == end, "credential length mismatch");
    ensure!(
        data[8..password_start]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "invalid username"
    );
    ensure!(
        data[password_start..end]
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b'='),
        "invalid password"
    );
    Ok((8..password_start, password_start..end))
}

fn make_secret_env(prefix: &[u8], value: &[u8]) -> Result<CString> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(prefix.len() + value.len()));
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(value);
    let result = CString::new(bytes.as_slice())?;
    bytes.zeroize();
    Ok(result)
}

fn build_argv(args: &Args) -> Result<Vec<CString>> {
    [
        "msfrpcd".to_owned(),
        "-f".to_owned(),
        "-a".to_owned(),
        "127.0.0.1".to_owned(),
        "-p".to_owned(),
        args.port.to_string(),
        "-t".to_owned(),
        args.token_timeout.to_string(),
    ]
    .into_iter()
    .map(|value| CString::new(value).map_err(Into::into))
    .collect()
}

fn build_environment(args: &Args, user: CString, password: CString) -> Result<Vec<CString>> {
    Ok(vec![
        CString::new(format!("PATH={EMBEDDED_PATH}"))?,
        prefixed_path(b"HOME=", &args.home)?,
        prefixed_path(b"MSF_CFGROOT_CONFIG=", &args.config_root)?,
        CString::new("LANG=C.UTF-8")?,
        user,
        password,
    ])
}

fn prefixed_path(prefix: &[u8], path: &Path) -> Result<CString> {
    let mut bytes = Vec::with_capacity(prefix.len() + path.as_os_str().as_bytes().len());
    bytes.write_all(prefix)?;
    bytes.write_all(path.as_os_str().as_bytes())?;
    CString::new(bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_parser_rejects_short_and_trailing_values() {
        let mut valid = b"FDM1\0\x04\0\x20user".to_vec();
        valid.extend_from_slice(&[b'x'; 32]);
        assert!(parse_credential(&valid).is_ok());
        valid.push(b'x');
        assert!(parse_credential(&valid).is_err());
    }
}
