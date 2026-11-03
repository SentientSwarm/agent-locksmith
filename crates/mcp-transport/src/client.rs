use crate::{Error, Limits, Metrics};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
pub struct Client {
    pub(crate) http: reqwest::Client,
    pub(crate) limits: Limits,
    pub(crate) metrics: Metrics,
    pub(crate) get_started: Arc<AtomicBool>,
}
impl Client {
    /// Additional CA roots only; certificate and hostname verification stay on.
    pub fn new(limits: Limits, roots: Vec<reqwest::Certificate>) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_millis(limits.connect_timeout_ms))
            .timeout(Duration::from_millis(limits.timeout_ms));
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        let http = builder.build().map_err(|_| Error("client_setup"))?;
        Ok(Self {
            http,
            limits,
            metrics: Metrics::default(),
            get_started: Arc::default(),
        })
    }
    pub fn metrics(&self) -> Metrics {
        self.metrics.clone()
    }
    pub(crate) fn begin_get(&self) -> Result<(), Error> {
        if self.get_started.swap(true, Ordering::Relaxed) {
            return Err(Error("get_renewal_unsupported"));
        }
        Ok(())
    }
}
