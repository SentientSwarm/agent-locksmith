//! `locksmith mtls ...` subcommands (T6.9).
//!
//! `revoke <serial>` adds a serial to the local emergency blocklist.
//! `list-blocklist` prints the current blocklist contents.
//! `crl-status` reports CRL freshness from the daemon (when reachable).
//!
//! For v0.7.0 the blocklist commands are local file operations — they
//! manipulate `mtls.blocklist_path` directly. The daemon picks up the
//! change on its next reload-poll (see `mtls::Blocklist`). A future
//! enhancement could route through an admin endpoint for remote
//! operation.

use std::path::PathBuf;

use clap::Subcommand;

use crate::client::CliError;
use crate::output::{Format, print};
use serde_json::json;

#[derive(Subcommand)]
pub enum MtlsCmd {
    /// Add a cert serial to the local emergency blocklist file.
    Revoke {
        /// Hex-encoded cert serial (case-insensitive).
        serial: String,
        /// Path to the blocklist file. Must match
        /// `listen.mtls.blocklist_path` in the daemon's config.
        #[arg(long)]
        blocklist_path: PathBuf,
        /// Optional reason — written as a `# comment` line above the
        /// serial for the next operator to find.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Print the current blocklist contents.
    ListBlocklist {
        #[arg(long)]
        blocklist_path: PathBuf,
    },
    /// Read the daemon's CRL state. Stub for v0.7.0 — currently
    /// reports the configured URL only; rich state surfaces in a
    /// future admin endpoint.
    CrlStatus,
}

pub async fn run(format: Format, cmd: MtlsCmd) -> Result<(), CliError> {
    match cmd {
        MtlsCmd::Revoke {
            serial,
            blocklist_path,
            reason,
        } => {
            let normalized = serial.trim().to_ascii_lowercase();
            let mut existing = std::fs::read_to_string(&blocklist_path).unwrap_or_default();
            if !existing.is_empty() && !existing.ends_with('\n') {
                existing.push('\n');
            }
            if let Some(reason) = reason {
                existing.push_str(&format!("# {reason}\n"));
            }
            existing.push_str(&normalized);
            existing.push('\n');
            if let Some(parent) = blocklist_path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&blocklist_path, existing)?;
            eprintln!(
                "Revoked serial {normalized} in {}",
                blocklist_path.display()
            );
            Ok(())
        }
        MtlsCmd::ListBlocklist { blocklist_path } => {
            let raw = std::fs::read_to_string(&blocklist_path).unwrap_or_default();
            let serials: Vec<String> = raw
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|s| s.to_string())
                .collect();
            print(&json!(serials), format);
            Ok(())
        }
        MtlsCmd::CrlStatus => {
            // v0.7.0 placeholder — real impl awaits an admin endpoint
            // exposing the CrlStore snapshot. For now we just point
            // operators at the daemon log for refresh-failure diagnosis.
            eprintln!(
                "crl-status: stub. Consult `journalctl -u locksmith | grep CRL` for refresh logs."
            );
            Ok(())
        }
    }
}
