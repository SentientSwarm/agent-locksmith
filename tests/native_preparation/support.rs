use super::native::Fixture;
use agent_locksmith::{
    native_authority::{runtime::Runtime, source::Current, store, writes},
    oauth::refresh::RefreshOwner,
};
use serde_json::{Value, json};

pub struct Setup {
    pub f: Fixture,
    pub rt: Runtime,
    pub agent: String,
}
impl Setup {
    pub async fn new() -> Self {
        let f = Fixture::new("").await;
        let agent = f
            .agents
            .get_by_name("caller")
            .await
            .unwrap()
            .unwrap()
            .public_id;
        let rt = Runtime::new(
            f.repo.clone(),
            f.catalog.clone(),
            None,
            vec![],
            RefreshOwner::default(),
        )
        .await
        .unwrap();
        Self { f, rt, agent }
    }
    pub async fn current(&self) -> Current {
        self.rt
            .current(
                &mut self.f.pool.acquire().await.unwrap(),
                &self.agent,
                "native",
            )
            .await
            .unwrap()
    }
    pub async fn publish(&self, tools: Vec<Value>) -> Value {
        let current = self.current().await;
        let mut tx = self.f.pool.begin().await.unwrap();
        let previous = store::observation(&mut tx, &current, &self.rt.run)
            .await
            .unwrap();
        let generation = store::reserve(
            &mut tx,
            &current,
            &self.rt.run,
            previous["generation"].as_str(),
        )
        .await
        .unwrap();
        let manifest = json!({"tools":tools.into_iter().map(|tool|json!({"observed_digest":agent_locksmith::native_authority::contract::observed(&tool),"tool":tool})).collect::<Vec<_>>()});
        store::publish(&mut tx, &current, &generation, &manifest)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        self.rt.snapshot(&self.agent, "native").await.unwrap()
    }
    pub async fn review(&self, snapshot: &Value, name: &str) -> Value {
        let entry = snapshot["observation"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["tool"]["name"] == name)
            .unwrap();
        let input=serde_json::from_value::<writes::Review>(json!({"source":snapshot["source"],"generation":snapshot["observation"]["generation"],"name":name,"observed_digest":entry["observed_digest"],"effect":"read"})).unwrap();
        self.rt.review(&self.agent, "native", input).await.unwrap()
    }
    pub fn replace(snapshot: &Value, tools: Value) -> writes::Replace {
        serde_json::from_value(json!({"source":snapshot["source"],"generation":snapshot["observation"]["generation"],"revision":snapshot["grant_revision"],"tools":tools})).unwrap()
    }
    pub async fn grant_for(&self, agent: &str, snapshot: &Value, tools: Value) {
        self.rt
            .replace(agent, "native", Self::replace(snapshot, tools))
            .await
            .unwrap();
    }
    pub async fn stale(&self, snapshot: &Value, run: &str) {
        let current = self.current().await;
        let mut c = self.f.pool.acquire().await.unwrap();
        assert!(
            store::ready(
                &mut c,
                &current,
                run,
                snapshot["observation"]["generation"].as_str().unwrap()
            )
            .await
            .is_err()
        );
    }
}
pub fn tool(name: &str) -> Value {
    json!({"name":name,"description":"Read one record","inputSchema":{"type":"object","properties":{"key":{"type":"string","maxLength":128}},"required":["key"],"additionalProperties":false}})
}
