//! The only admitted native tool submission path.
use super::{
    Error, Result, call_result, contract, control::Control, destination, diagnostics::Trace,
    effective::Snapshot, protected, runtime::Runtime, source::Source, wire,
};
use crate::repo::audit::AuditRepository;
use secrecy::ExposeSecret;
use serde_json::Value;

pub struct Invocation {
    pub agent: String,
    pub connection: String,
    pub name: String,
    pub source: Source,
    pub digest: String,
    pub arguments: Value,
}
impl Runtime {
    pub async fn dispatch(
        &self,
        mut call: Invocation,
        control: Control,
        audit: &AuditRepository,
    ) -> Result<Value> {
        let mut trace = Trace::new(&call.agent, &call.connection)?;
        let result = self
            .scoped(async {
                let result = control
                    .run(self.invoke(&mut call, &control, audit, &mut trace))
                    .await;
                let result = trace.checked.clone().map(Ok).unwrap_or(result);
                trace.finish(audit, &control, &result).await;
                result
            })
            .await;
        trace.interrupted(&result);
        trace.checked.take().map(Ok).unwrap_or(result)
    }
    async fn capture(&self, call: &mut Invocation, trace: &mut Trace) -> Result<Snapshot> {
        let mut tx = self.repo.pool.begin().await?;
        let snapshot = self
            .effective(&mut tx, &call.agent, &call.connection)
            .await?;
        snapshot.current.matches(&call.source)?;
        let approved = snapshot.tool(&call.name, &call.digest)?;
        trace.approved(call);
        call.arguments = protected::merge(
            &protected::Reviewed {
                full: approved.tool.clone(),
                public: approved.public.clone(),
                context: approved.context.clone(),
            },
            &call.arguments,
        )?;
        tx.commit().await?;
        Ok(snapshot)
    }
    async fn invoke(
        &self,
        call: &mut Invocation,
        control: &Control,
        audit: &AuditRepository,
        trace: &mut Trace,
    ) -> Result<Value> {
        let before = self.capture(call, trace).await?;
        let reg = &before.current.admission.registration;
        let bearer = self
            .materialize(&call.agent, &call.connection, &call.source)
            .await?;
        if let Some(secret) = &bearer {
            contract::screen(&call.arguments, secret.expose_secret())?;
        }
        let client = self.client(reg).await?;
        let mut upstream = wire::Connection {
            client,
            endpoint: reg.upstream.clone().into(),
            bearer: bearer.as_ref().map(ExposeSecret::expose_secret),
            session: None,
        };
        let result = self
            .prepared(call, &before, control, audit, &mut upstream, trace)
            .await;
        upstream.cleanup().await;
        result
    }
    async fn prepared(
        &self,
        call: &Invocation,
        before: &Snapshot,
        control: &Control,
        audit: &AuditRepository,
        upstream: &mut wire::Connection<'_>,
        trace: &mut Trace,
    ) -> Result<Value> {
        upstream.initialize().await?;
        self.commit_call(call, before, control, audit, trace)
            .await?;
        control.check()?;
        before.fresh()?;
        trace.submitted();
        let result = upstream
            .call(&call.name, &call.arguments)
            .await
            .and_then(|v| {
                call_result::checked(&before.tool(&call.name, &call.digest)?.tool, &v)?;
                Ok(v)
            });
        if let Ok(value) = &result {
            trace.checked(value);
        }
        result.map_err(|_| Error("tool_outcome_unknown"))
    }

    async fn client(
        &self,
        reg: &crate::registrations::Registration,
    ) -> Result<locksmith_mcp_transport::Client> {
        let private = reg
            .mcp
            .as_ref()
            .is_some_and(|c| c.allow_private_destination);
        let addresses = destination::resolve(&reg.upstream, private, &self.listeners).await?;
        locksmith_mcp_transport::Client::pinned(
            Default::default(),
            self.roots.clone(),
            &reg.upstream,
            addresses,
            1024 * 1024,
            call_result::envelope,
        )
        .map_err(|_| Error("upstream_client"))
    }
}
