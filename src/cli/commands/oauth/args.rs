use clap::{Args, Subcommand};

#[derive(Subcommand, Debug)]
pub enum OauthCmd {
    /// Bootstrap a new OAuth session for `<name>` with a
    /// pre-obtained refresh token. v1.0 manual path: complete the
    /// provider's own OAuth flow first (e.g., `gh auth login` for
    /// copilot, `claude auth` for anthropic-oauth) and pass the
    /// refresh token here. Future versions ship the interactive
    /// flow inside this command. Pending custody requires local revoke and
    /// freshly obtained credentials; never replay an uncertain refresh token.
    Bootstrap(BootstrapArgs),
    /// Show status, refresh_pending and reconnect_required for `<name>`.
    Status {
        name: String,
        /// Phase G: session label (defaults to "default"). Use to
        /// inspect a specific per-agent session under a registration.
        #[arg(long)]
        label: Option<String>,
    },
    /// Revoke (delete locally) the OAuth session for `<name>`
    /// [--label <label>]. Idempotent. Does NOT call the provider's
    /// revoke endpoint.
    Revoke {
        name: String,
        /// Phase G: session label (defaults to "default").
        #[arg(long)]
        label: Option<String>,
    },
    /// List all OAuth sessions across all registrations + labels.
    /// Phase G; useful for spotting orphaned per-agent sessions.
    List,
}

#[derive(Args, Debug)]
pub struct BootstrapArgs {
    /// Registration name (must already exist as a kind=tool or
    /// kind=model with an OAuth AuthSpec).
    pub name: String,

    /// Phase G: session label. Defaults to "default" — single shared
    /// session per registration. Use distinct labels (e.g., "hermes",
    /// "openclaw") when bootstrapping per-agent OAuth from different
    /// upstream accounts. See concepts/per-agent-credentials.md for
    /// the single-grant trap explanation.
    #[arg(long)]
    pub label: Option<String>,

    /// Refresh token obtained out-of-band from the provider's OAuth
    /// flow. WARNING: this argument transits the shell history. Prefer
    /// `--refresh-token-stdin` for production use.
    #[arg(long, conflicts_with = "refresh_token_stdin")]
    pub refresh_token: Option<String>,

    /// Read the refresh token from stdin (one line, trimmed). Use this
    /// in scripts / pipelines to keep the token out of shell history.
    #[arg(long, conflicts_with = "refresh_token")]
    pub refresh_token_stdin: bool,
}
