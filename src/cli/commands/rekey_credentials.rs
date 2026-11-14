//! `locksmith rekey-credentials`: offline re-key of stored credential values.
//! Deliberately offline: OS access to the database is owner authority.
//! Keys come only from owner-only files, never argv or the environment.
use agent_locksmith::secret::CredentialSealingKey;
use agent_locksmith::secret::rekey::{self, RekeyError};
use clap::Args;
use secrecy::zeroize::Zeroizing;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct RekeyArgs {
    /// Existing SQLite database; stop the daemon and back it up first.
    #[arg(long)]
    database: PathBuf,
    /// File holding the current base64 credential sealing key (mode 0600 or 0400).
    #[arg(long)]
    old_key_file: PathBuf,
    /// File holding the new base64 credential sealing key (mode 0600 or 0400).
    #[arg(long)]
    new_key_file: PathBuf,
}

/// Exit code 2 for unusable input, 1 for a run that failed.
pub async fn run(args: RekeyArgs) -> Result<(), (u8, String)> {
    let (old_text, old) = read_key(&args.old_key_file)?;
    let (new_text, new) = read_key(&args.new_key_file)?;
    if old_text.trim() == new_text.trim() {
        return Err((2, "the old and new key files hold the same key".into()));
    }
    match rekey::rekey_credentials(&args.database, &old, &new).await {
        Ok(n) => {
            println!("{{\"rekeyed\":{n}}}");
            Ok(())
        }
        Err(e @ RekeyError::WrongKey) => Err((1, format!("{e}; nothing was changed"))),
        Err(e) => Err((1, e.to_string())),
    }
}

/// A key file and the key in it. Non-regular files (for example `/dev/fd/N`
/// from process substitution) skip the mode check: they have no stored copy.
fn read_key(path: &Path) -> Result<(Zeroizing<String>, CredentialSealingKey), (u8, String)> {
    let shown = path.display();
    let fail = |e: std::io::Error| (2, format!("{shown}: {e}"));
    // One open: the mode is checked on the handle that is read, so the path
    // cannot be swapped between the check and the read.
    let mut file = std::fs::File::open(path).map_err(fail)?;
    let meta = file.metadata().map_err(fail)?;
    if meta.is_file() && meta.permissions().mode() & 0o077 != 0 {
        return Err((
            2,
            format!("{shown}: readable by group or others; chmod 600 it"),
        ));
    }
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text).map_err(fail)?;
    let key = CredentialSealingKey::from_b64(text.trim())
        .map_err(|_| (2, format!("{shown}: not a base64 32-byte key")))?;
    Ok((text, key))
}
