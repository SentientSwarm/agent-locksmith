use crate::fixture::{Agent, Fixture, SENTINELS};
use agent_locksmith::repo::audit::{AuditFilter, AuditPage};

impl Fixture {
    pub async fn denied(&self, agent: &Agent, status: u16, code: &str, cause: &str) {
        let before = self.count().await;
        let logs = crate::logs::Capture::default();
        let _guard = logs.start();
        let response = self.call(agent).await;
        assert_eq!(
            self.count().await,
            before,
            "denied admission dispatched upstream"
        );
        response.assert_status(axum::http::StatusCode::from_u16(status).unwrap());
        assert_eq!(response.json::<serde_json::Value>()["error"]["code"], code);
        self.safe_surfaces(&format!("{}{}", response.text(), logs.text()))
            .await;
        let rows = self
            .audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap();
        assert!(rows.iter().any(|r| {
            r.status == Some(status)
                && r.tool.as_deref() == Some("api")
                && r.agent_public_id.as_deref() == Some(&agent.public_id)
                && r.details
                    .as_ref()
                    .is_some_and(|d| d.to_string().contains(cause))
        }));
    }

    pub async fn allowed(&self, agent: &Agent, account: &str) {
        let before = self.count().await;
        let logs = crate::logs::Capture::default();
        let _guard = logs.start();
        let response = self.call(agent).await;
        response.assert_status_ok();
        assert_eq!(response.text(), account);
        assert_eq!(self.count().await, before + 1);
        self.safe_surfaces(&format!("{}{}", response.text(), logs.text()))
            .await;
        let rows = self
            .audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap();
        assert!(rows.iter().any(|r| {
            r.status == Some(200)
                && r.agent_public_id.as_deref() == Some(&agent.public_id)
                && r.details
                    .as_ref()
                    .is_some_and(|d| d["auth_source"] == "agent_override")
        }));
    }

    pub async fn safe_surfaces(&self, response: &str) {
        let rows = self
            .audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap();
        let audits = format!("{rows:?}");
        let reads = format!("{:?}", self.bindings.list_all().await.unwrap_or_default());
        for secret in SENTINELS {
            assert!(!format!("{response}{audits}{reads}").contains(secret));
        }
    }
}
