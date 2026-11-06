use clap::{Args, Subcommand};

#[derive(Subcommand, Debug)]
pub enum OauthCmd {
    /// Manage an owner-bound protected confidential client generation.
    Client {
        #[command(subcommand)]
        command: super::client::ClientCmd,
    },
    /// Create one supported owner-bound consent attempt; prints its URL once.
    /// No browser is opened and no agent authority is granted.
    Connect {
        name: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        client_generation: u64,
        /// Configured redirect profile. Slack without response iss requires /oauth/callback/slack.
        #[arg(long)]
        redirect_profile: String,
        #[arg(long)]
        expected_config_revision: i64,
        /// Exact requested scopes. Slack requires search:read.public,channels:history.
        #[arg(long, value_delimiter = ',', default_value = "read")]
        scopes: Vec<String>,
    },
    /// Read owner-bound attempt state. Never returns the authorization URL.
    AttemptStatus {
        name: String,
        /// Attempt ids are URL-safe base64 and may begin with `-`.
        #[arg(allow_hyphen_values = true)]
        attempt: String,
    },
    /// Cancel an owned attempt; a committed account is retained.
    Cancel {
        name: String,
        /// Attempt ids are URL-safe base64 and may begin with `-`.
        #[arg(allow_hyphen_values = true)]
        attempt: String,
    },
    /// Read owner-bound supported account metadata and current revisions.
    AccountStatus {
        name: String,
        #[arg(long)]
        label: String,
    },
    /// Manually refresh owned supported custody with its current revision.
    /// Pending/uncertain custody requires disconnect and fresh consent.
    Refresh {
        name: String,
        #[arg(long)]
        label: String,
        /// Revisions are URL-safe base64 and may begin with `-`.
        #[arg(long, allow_hyphen_values = true)]
        if_match: String,
    },
    /// Disconnect owned supported custody with its current opaque revision.
    Disconnect {
        name: String,
        #[arg(long)]
        label: String,
        /// Revisions are URL-safe base64 and may begin with `-`.
        #[arg(long, allow_hyphen_values = true)]
        if_match: String,
    },
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
    /// List legacy OAuth sessions across all registrations + labels.
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
