//! `locksmith mtls ...` subcommands (T6.9).
//!
//! `revoke <serial>` adds a serial to the local emergency blocklist.
//! `list-blocklist` prints the current blocklist contents.
//! `crl-status` is a placeholder that points at the daemon log.
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
    /// Placeholder: does not contact the daemon or report CRL state.
    /// Read CRL state from the daemon log (`CRL applied`, `CRL refresh
    /// failed`, `CRL refused`) and from `mtls-crl-cache.pem` beside the
    /// database file.
    CrlStatus,
}

pub async fn run(format: Format, cmd: MtlsCmd) -> Result<(), CliError> {
    match cmd {
        MtlsCmd::Revoke {
            serial,
            blocklist_path,
            reason,
        } => {
            let normalized = agent_locksmith::mtls::blocklist::canonical_serial(&serial)
                .ok_or_else(|| CliError::Usage(format!("`{serial}` is not a hex serial")))?;
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
            agent_locksmith::mtls::blocklist::write_atomic_keeping_owner(
                &blocklist_path,
                existing.as_bytes(),
            )?;
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
            // Placeholder until an admin endpoint exposes the CrlStore
            // snapshot; points operators at where CRL state is recorded.
            eprintln!(
                "crl-status: not implemented. Read CRL state from the daemon log \
                 (`CRL applied`, `CRL refresh failed`, `CRL refused`) and from \
                 mtls-crl-cache.pem beside the database file."
            );
            Ok(())
        }
    }
}
