//! Deliberately offline: OS access to the database is owner authority.
use agent_locksmith::binding_migration::{self, Error, Plan};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ArgsOffline {
    #[command(subcommand)]
    cmd: Command,
}
#[derive(Subcommand, Debug)]
enum Command {
    /// Read-only reference inventory; redirect JSON to a private plan file.
    Preview(Database),
    /// Atomically apply selected:true proposals from a reviewed JSON plan.
    Apply {
        #[command(flatten)]
        database: Database,
        /// Reviewed preview JSON. Only selected flags may be changed.
        #[arg(long)]
        plan: PathBuf,
    },
}
#[derive(Args, Debug)]
struct Database {
    /// Existing SQLite database; stop daemon and take a SQLite-safe backup first.
    #[arg(long)]
    database: PathBuf,
    /// Optional legacy YAML inventory. Never expanded, resolved or imported.
    #[arg(long)]
    legacy_config: Option<PathBuf>,
}
pub async fn run(args: ArgsOffline) -> Result<(), Error> {
    match args.cmd {
        Command::Preview(db) => {
            let plan =
                binding_migration::preview(&db.database, db.legacy_config.as_deref()).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&plan).map_err(|_| Error::Invalid)?
            );
        }
        Command::Apply { database: db, plan } => {
            let bytes = std::fs::read(plan).map_err(|_| Error::Invalid)?;
            let plan: Plan = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
            let count =
                binding_migration::apply(&db.database, &plan, db.legacy_config.as_deref()).await?;
            println!("{{\"inserted\":{count}}}");
        }
    }
    Ok(())
}
