use super::{Result, grants, runtime::Runtime, source::Source, store};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub source: Source,
    pub generation: String,
    pub name: String,
    pub observed_digest: String,
    pub effect: String,
    #[serde(default)]
    pub context: Map<String, Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replace {
    pub source: Source,
    pub generation: String,
    #[serde(deserialize_with = "required_nullable")]
    pub revision: Option<String>,
    pub tools: Vec<grants::Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observe {
    pub source: Source,
    #[serde(deserialize_with = "required_nullable")]
    pub generation: Option<String>,
}
fn required_nullable<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
impl Runtime {
    pub async fn review(&self, agent: &str, name: &str, input: Review) -> Result<Value> {
        self.review_for(None, agent, name, input).await
    }
    pub async fn review_for(
        &self,
        owner: Option<&str>,
        agent: &str,
        name: &str,
        input: Review,
    ) -> Result<Value> {
        let bearer = if input.context.is_empty() {
            None
        } else {
            self.materialize_for(Some(owner), agent, name, &input.source)
                .await?
        };
        let mut tx = self.repo.pool.begin().await?;
        let current = self.current_for(&mut tx, owner, agent, name).await?;
        current.matches(&input.source)?;
        let manifest = store::ready(&mut tx, &current, &self.run, &input.generation).await?;
        let value = grants::review(
            &mut tx,
            &current,
            &manifest,
            &input,
            bearer.as_ref().map(ExposeSecret::expose_secret),
        )
        .await?;
        current.fresh()?;
        tx.commit().await?;
        Ok(value)
    }
    pub async fn replace(&self, agent: &str, name: &str, input: Replace) -> Result<Value> {
        self.replace_for(None, agent, name, input).await
    }
    pub async fn replace_for(
        &self,
        owner: Option<&str>,
        agent: &str,
        name: &str,
        input: Replace,
    ) -> Result<Value> {
        let mut tx = self.repo.pool.begin().await?;
        let current = self.current_for(&mut tx, owner, agent, name).await?;
        current.matches(&input.source)?;
        let manifest = store::ready(&mut tx, &current, &self.run, &input.generation).await?;
        let revision = grants::replace(
            &mut tx,
            &current,
            &manifest,
            input.revision.as_deref(),
            &input.tools,
        )
        .await?;
        current.fresh()?;
        tx.commit().await?;
        Ok(
            json!({"source":current.source,"grant_revision":revision,"tools":input.tools,"prepared_only":false,"callable":!input.tools.is_empty(),"requires_session_list":true}),
        )
    }
}
