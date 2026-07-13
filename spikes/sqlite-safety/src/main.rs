use std::path::Path;

use anyhow::{Context, Result, bail};
use sqlite_safety::{
    crash_writer, lock_holder, lock_probe, run_full_gate, set_private_umask, write_evidence,
};

fn main() -> Result<()> {
    set_private_umask();
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("evidence") => {
            let output = arguments.get(2).context("missing evidence output path")?;
            let temporary = tempfile::tempdir()?;
            let executable = std::env::current_exe()?;
            let evidence = run_full_gate(temporary.path(), &executable)?;
            write_evidence(Path::new(output), &evidence)?;
        }
        Some("crash-writer") => {
            crash_writer(
                Path::new(arguments.get(2).context("missing database path")?),
                Path::new(arguments.get(3).context("missing ack path")?),
                false,
            )?;
        }
        Some("abort-writer") => {
            crash_writer(
                Path::new(arguments.get(2).context("missing database path")?),
                Path::new(arguments.get(3).context("missing ack path")?),
                true,
            )?;
        }
        Some("lock-holder") => {
            let hold_ms = arguments
                .get(4)
                .context("missing hold duration")?
                .parse::<u64>()?;
            lock_holder(
                Path::new(arguments.get(2).context("missing lock path")?),
                Path::new(arguments.get(3).context("missing ready path")?),
                hold_ms,
            )?;
        }
        Some("lock-probe") => {
            let code = lock_probe(
                arguments.get(2).context("missing lock mode")?,
                Path::new(arguments.get(3).context("missing lock path")?),
                Path::new(arguments.get(4).context("missing database path")?),
            )?;
            std::process::exit(code);
        }
        _ => bail!(
            "usage: sqlite-safety evidence <output> | crash-writer <db> <ack> | abort-writer <db> <ack> | lock-holder <lock> <ready> <ms> | lock-probe <writer|readonly> <lock> <db>"
        ),
    }
    Ok(())
}
