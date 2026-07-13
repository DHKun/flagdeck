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
    target: PathBuf,
    home: PathBuf,
    config_root: PathBuf,
    port: u16,
    token_timeout: u16,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("credential launcher failed: {error:#}");
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

    let target = path_cstring(&config.target)?;
    let argv = build_argv(&config)?;
    let environment = build_environment(&config, user_env, password_env)?;
    let argv_refs: Vec<&CStr> = argv.iter().map(CString::as_c_str).collect();
    let environment_refs: Vec<&CStr> = environment.iter().map(CString::as_c_str).collect();

    execve(&target, &argv_refs, &environment_refs)
        .with_context(|| format!("execve failed for {}", config.target.display()))?;
    Ok(())
}

fn parse_args(arguments: impl Iterator<Item = OsString>) -> Result<Args> {
    let mut channel = None;
    let mut source = None;
    let mut target = None;
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
            Some("--target") => target = Some(PathBuf::from(value)),
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
        target: target.context("--target is required")?,
        home: home.context("--home is required")?,
        config_root: config_root.context("--config-root is required")?,
        port: port.context("--port is required")?,
        token_timeout: token_timeout.context("--token-timeout is required")?,
    })
}

fn parse_u16(value: &OsStr, label: &str) -> Result<u16> {
    let text = value
        .to_str()
        .with_context(|| format!("{label} is not UTF-8"))?;
    let parsed = text
        .parse::<u16>()
        .with_context(|| format!("invalid {label}"))?;
    ensure!(parsed > 0, "{label} must be positive");
    Ok(parsed)
}

fn validate_runtime_paths(args: &Args) -> Result<()> {
    ensure!(args.target.is_absolute(), "target must be absolute");
    ensure!(args.home.is_absolute(), "home must be absolute");
    ensure!(
        args.config_root.is_absolute(),
        "config root must be absolute"
    );
    ensure!(args.target.is_file(), "target is not a regular file");
    ensure!(args.home.is_dir(), "home is not a directory");
    ensure!(args.config_root.is_dir(), "config root is not a directory");
    if args.channel == Channel::DirectSocket {
        let source = Path::new(&args.source);
        ensure!(source.is_absolute(), "socket path must be absolute");
        let metadata = fs::symlink_metadata(source).context("cannot inspect credential socket")?;
        ensure!(
            metadata.file_type().is_socket(),
            "credential source is not a socket"
        );
    } else {
        validate_credential_id(&args.source)?;
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
        "credential ID contains invalid bytes"
    );
    Ok(())
}

fn read_credential(args: &Args) -> Result<Zeroizing<Vec<u8>>> {
    let mut reader: Box<dyn Read> = match args.channel {
        Channel::DirectSocket => {
            let stream = UnixStream::connect(Path::new(&args.source))
                .context("cannot connect to credential socket")?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .context("cannot set credential socket timeout")?;
            Box::new(stream)
        }
        Channel::SystemdCredential => {
            let directory = env::var_os("CREDENTIALS_DIRECTORY")
                .context("CREDENTIALS_DIRECTORY is unavailable")?;
            let path = PathBuf::from(directory).join(&args.source);
            let metadata =
                fs::symlink_metadata(&path).context("cannot inspect systemd credential")?;
            ensure!(
                metadata.file_type().is_file(),
                "systemd credential is not a file"
            );
            ensure!(
                usize::try_from(metadata.len()).unwrap_or(usize::MAX) <= MAX_CREDENTIAL_BYTES,
                "systemd credential exceeds limit"
            );
            Box::new(File::open(path).context("cannot open systemd credential")?)
        }
    };

    let mut data = Zeroizing::new(Vec::with_capacity(128));
    reader
        .by_ref()
        .take(u64::try_from(MAX_CREDENTIAL_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut data)
        .context("cannot read credential payload")?;
    ensure!(
        data.len() <= MAX_CREDENTIAL_BYTES,
        "credential payload exceeds limit"
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
    let user_start = 8;
    let password_start = user_start + user_length;
    let end = password_start + password_length;
    ensure!(data.len() == end, "credential length mismatch");
    ensure!(
        data[user_start..password_start]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "username contains invalid bytes"
    );
    ensure!(
        data[password_start..end]
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b'='),
        "password contains invalid bytes"
    );
    Ok((user_start..password_start, password_start..end))
}

fn make_secret_env(prefix: &[u8], value: &[u8]) -> Result<CString> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(prefix.len() + value.len()));
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(value);
    let result = CString::new(bytes.as_slice()).context("secret contains NUL")?;
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
        "-n".to_owned(),
    ]
    .into_iter()
    .map(|value| CString::new(value).context("argv contains NUL"))
    .collect()
}

fn build_environment(
    args: &Args,
    user_env: CString,
    password_env: CString,
) -> Result<Vec<CString>> {
    Ok(vec![
        CString::new(format!("PATH={EMBEDDED_PATH}"))?,
        prefixed_path_cstring(b"HOME=", &args.home)?,
        prefixed_path_cstring(b"MSF_CFGROOT_CONFIG=", &args.config_root)?,
        CString::new("LANG=C.UTF-8")?,
        user_env,
        password_env,
    ])
}

fn prefixed_path_cstring(prefix: &[u8], path: &Path) -> Result<CString> {
    let mut bytes = Vec::with_capacity(prefix.len() + path.as_os_str().as_bytes().len());
    bytes.write_all(prefix)?;
    bytes.write_all(path.as_os_str().as_bytes())?;
    CString::new(bytes).context("path contains NUL")
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("target path contains NUL")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(user: &[u8], password: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&u16::try_from(user.len()).unwrap().to_be_bytes());
        output.extend_from_slice(&u16::try_from(password.len()).unwrap().to_be_bytes());
        output.extend_from_slice(user);
        output.extend_from_slice(password);
        output
    }

    #[test]
    fn parses_bounded_payload() {
        let data = payload(b"fd_user-1", &[b'X'; 32]);
        let (user, password) = parse_credential(&data).unwrap();
        assert_eq!(&data[user], b"fd_user-1");
        assert_eq!(&data[password], &[b'X'; 32]);
    }

    #[test]
    fn rejects_short_password_and_trailing_bytes() {
        assert!(parse_credential(&payload(b"user", &[b'X'; 31])).is_err());
        let mut trailing = payload(b"user", &[b'X'; 32]);
        trailing.push(b'X');
        assert!(parse_credential(&trailing).is_err());
    }

    #[test]
    fn rejects_unsafe_ids_and_zero_ports() {
        assert!(validate_credential_id(OsStr::new("../secret")).is_err());
        assert!(parse_u16(OsStr::new("0"), "port").is_err());
    }
}
