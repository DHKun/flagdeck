use std::path::PathBuf;

use anyhow::{Context, Result};
use sqlite_safety::run_full_gate;

#[test]
fn r0_sqlite_gate_passes() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let executable = PathBuf::from(
        std::env::var("CARGO_BIN_EXE_sqlite-safety")
            .context("Cargo did not expose sqlite-safety test binary")?,
    );
    let evidence = run_full_gate(temporary.path(), &executable)?;
    assert_eq!(evidence.status, "PASS");
    assert!(evidence.pragma.sqlite_version_number >= 3_051_003);
    assert_eq!(evidence.stress.inserted_rows, 2_000);
    assert!(evidence.backup.active_writes_observed);
    assert_eq!(evidence.backup.foreign_key_violations, 0);
    assert_eq!(evidence.crash.integrity_check, "ok");
    assert!(evidence.lock.writer_rejected);
    assert!(evidence.lock.readonly_succeeded);
    assert!(evidence.migration.failed_migration_rolled_back);
    assert!(evidence.migration.raw_copy_rejected);
    Ok(())
}
