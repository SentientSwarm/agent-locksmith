use crate::{Client, Error, Limits, ResponseValidator};
use reqwest::{
    Certificate, Url,
    dns::{Addrs, Name, Resolve, Resolving},
};
use std::{net::SocketAddr, sync::Arc};

struct Resolver {
    host: String,
    addresses: Vec<SocketAddr>,
}
impl Resolve for Resolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allowed = name.as_str().eq_ignore_ascii_case(&self.host);
        let addresses = self.addresses.clone();
        Box::pin(async move {
            if !allowed {
                return Err("pinned_dns_name".into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}
impl Client {
    /// Caller must approve every address first. Exact endpoint, no fallback DNS.
    /// The aggregate budget is shared across clones and all response paths.
    pub fn pinned(
        limits: Limits,
        roots: Vec<Certificate>,
        endpoint: &str,
        addresses: Vec<SocketAddr>,
        aggregate_bytes: usize,
        validator: ResponseValidator,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let url = Url::parse(endpoint).map_err(|_| Error("url"))?;
        validate(&url, &addresses, aggregate_bytes)?;
        let host = url
            .host_str()
            .ok_or(Error("url"))?
            .trim_matches(['[', ']'])
            .to_owned();
        let mut builder =
            Self::builder(limits).dns_resolver(Arc::new(Resolver { host, addresses }));
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        let mut client = Self::finish(builder, limits)?;
        client.endpoint = Some(url);
        client.validator = Some(validator);
        client.metrics.budget(aggregate_bytes);
        Ok(client)
    }
}
fn validate(url: &Url, addresses: &[SocketAddr], budget: usize) -> Result<(), Error> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || addresses.is_empty()
        || addresses.len() > 32
        || budget == 0
        || addresses
            .iter()
            .any(|a| Some(a.port()) != url.port_or_known_default())
    {
        return Err(Error("pinned_endpoint"));
    }
    let host = url.host_str().ok_or(Error("url"))?.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && addresses.iter().any(|a| a.ip() != ip)
    {
        return Err(Error("pinned_address"));
    }
    Ok(())
}
