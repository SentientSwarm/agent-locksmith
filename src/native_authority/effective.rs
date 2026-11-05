//! One current intersection for listing, preparation and final admission.
use super::{
    Error, Result, contract, grants, protected,
    runtime::Runtime,
    source::{Current, Source},
    store,
};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct Approved {
    pub digest: String,
    pub effect: String,
    pub tool: Value,
    pub public: Value,
    pub context: serde_json::Map<String, Value>,
}
pub struct Snapshot {
    pub current: Current,
    pub generation: Option<String>,
    pub revision: Option<String>,
    pub observed_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub tools: BTreeMap<String, Approved>,
}
#[derive(Default)]
pub struct Pins(pub Option<(Source, BTreeMap<String, String>)>);
impl Pins {
    pub fn list(&mut self, snapshot: &Snapshot) -> Result<Vec<Value>> {
        let (source, pins) = self.0.get_or_insert_with(|| {
            (
                snapshot.current.source.clone(),
                snapshot
                    .tools
                    .iter()
                    .map(|(n, t)| (n.clone(), t.digest.clone()))
                    .collect(),
            )
        });
        snapshot.current.matches(source)?;
        Ok(snapshot
            .tools
            .iter()
            .filter(|(n, t)| pins.get(*n) == Some(&t.digest))
            .map(|(_, t)| t.public.clone())
            .collect())
    }
    pub fn selected(&self, name: &str) -> Result<(Source, String)> {
        let (s, p) = self.0.as_ref().ok_or(Error("tools_list_required"))?;
        Ok((
            s.clone(),
            p.get(name).ok_or(Error("tool_not_approved"))?.clone(),
        ))
    }
}
impl Runtime {
    pub async fn effective(
        &self,
        c: &mut SqliteConnection,
        agent: &str,
        name: &str,
    ) -> Result<Snapshot> {
        let current = self.current(c, agent, name).await?;
        let revision = store::revision(c, &current).await?;
        let expires_at = sqlx::query_scalar("SELECT expires_at FROM agents WHERE id=?")
            .bind(current.agent)
            .fetch_one(&mut *c)
            .await?;
        let rows = sqlx::query("SELECT g.name,g.contract_digest,r.observed_digest,r.contract FROM native_tool_grants g JOIN native_reviews r USING(instance,account_key,name,contract_digest) WHERE g.agent_id=? AND g.instance=? AND g.account_key=? ORDER BY g.name LIMIT 33")
            .bind(current.agent).bind(&current.source.instance).bind(&current.source.account_key).fetch_all(&mut *c).await?;
        if rows.len() > 32 {
            return Err(Error("grant_limit"));
        }
        let observation = store::observation(c, &current, &self.run).await?;
        let mut snapshot = Snapshot::empty(current, revision, expires_at, &observation);
        snapshot.current.fresh()?;
        if rows.is_empty() {
            return Ok(snapshot);
        }
        fresh(&observation)?;
        for row in rows {
            append(&mut snapshot, &observation["manifest"], row)?;
        }
        Ok(snapshot)
    }
}
fn fresh(observation: &Value) -> Result<()> {
    if observation["fresh"] == true {
        Ok(())
    } else {
        Err(Error("observation_required"))
    }
}
fn append(s: &mut Snapshot, manifest: &Value, row: sqlx::sqlite::SqliteRow) -> Result<()> {
    let name: String = row.get("name");
    let reviewed: Value = crate::native::json::parse(row.get::<&str, _>("contract").as_bytes())
        .map_err(|_| Error("review_invalid"))?;
    let digest: String = row.get("contract_digest");
    let observed = grants::observed(manifest, &name)?;
    if observed["observed_digest"] != row.get::<String, _>("observed_digest")
        || reviewed["tool"] != observed["tool"]
        || contract::digest("locksmith-native-contract-v1", &reviewed) != digest
    {
        return Err(Error("review_invalid"));
    }
    let checked = protected::load(&reviewed)?;
    s.tools.insert(
        name,
        Approved {
            digest,
            effect: reviewed["effect"]
                .as_str()
                .ok_or(Error("review_invalid"))?
                .into(),
            tool: checked.full,
            public: checked.public,
            context: checked.context,
        },
    );
    Ok(())
}
impl Snapshot {
    fn empty(
        current: Current,
        revision: Option<String>,
        expires_at: Option<i64>,
        observation: &Value,
    ) -> Self {
        Self {
            current,
            revision,
            expires_at,
            generation: observation["generation"].as_str().map(str::to_owned),
            observed_at: observation["observed_at"].as_i64(),
            tools: BTreeMap::new(),
        }
    }

    pub fn tool(&self, name: &str, digest: &str) -> Result<&Approved> {
        self.tools
            .get(name)
            .filter(|t| t.digest == digest)
            .ok_or(Error("tool_not_approved"))
    }
    pub fn matches(&self, previous: &Self) -> Result<()> {
        self.current.matches(&previous.current.source)?;
        if self.generation != previous.generation || self.revision != previous.revision {
            return Err(Error("authority_changed"));
        }
        self.fresh()
    }
    pub fn fresh(&self) -> Result<()> {
        self.current.fresh()?;
        if self.expires_at.is_some_and(|t| t <= store::now()) {
            return Err(Error("source_unavailable"));
        }
        if self
            .observed_at
            .is_some_and(|t| t <= store::now() && store::now() - t < 60)
        {
            Ok(())
        } else {
            Err(Error("observation_required"))
        }
    }
}
