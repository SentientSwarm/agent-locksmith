//! AGENT-281 — the request gate for a route's [`RoutePolicy`].
//!
//! Runs after admission and before rate limits, credential resolution or
//! any upstream contact, so a refused request costs nothing and reveals
//! nothing. The check is on the raw (still percent-encoded) URI path, and
//! the joined upstream path must equal an allowed path exactly: no dot
//! segments, doubled slashes, encodings or trailing extras get through.

use axum::http::Method;

use crate::registrations::RoutePolicy;

/// Databento Historical metadata methods. All are read-only and free.
pub const DATABENTO_METADATA: &[&str] = &[
    "list_publishers",
    "list_datasets",
    "list_schemas",
    "list_fields",
    "list_unit_prices",
    "get_dataset_condition",
    "get_dataset_range",
    "get_record_count",
    "get_billable_size",
    "get_cost",
];

/// Why a request was refused; recorded in the audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Method,
    Path,
    /// The stored policy is unknown to this build.
    Policy,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Method => "method",
            Self::Path => "path",
            Self::Policy => "policy",
        }
    }
}

/// `raw_path` is the request URI path as received (`/api/<route>/...`).
pub fn admit(
    policy: RoutePolicy,
    upstream: &str,
    route: &str,
    method: &Method,
    raw_path: &str,
) -> Result<(), Refusal> {
    match policy {
        RoutePolicy::DatabentoHistorical => databento(upstream, route, method, raw_path),
        RoutePolicy::Unrecognized => Err(Refusal::Policy),
    }
}

fn databento(upstream: &str, route: &str, method: &Method, raw_path: &str) -> Result<(), Refusal> {
    if method != Method::GET && method != Method::POST {
        return Err(Refusal::Method);
    }
    let rest = raw_path
        .strip_prefix(&format!("/api/{route}/"))
        .ok_or(Refusal::Path)?;
    let base = reqwest::Url::parse(upstream).map_err(|_| Refusal::Path)?;
    let joined = format!("{}/{}", base.path().trim_end_matches('/'), rest);
    let method_name = joined.strip_prefix("/v0/metadata.").ok_or(Refusal::Path)?;
    if DATABENTO_METADATA.contains(&method_name) {
        Ok(())
    } else {
        Err(Refusal::Path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "https://hist.databento.com";

    fn check(upstream: &str, method: Method, path: &str) -> Result<(), Refusal> {
        admit(
            RoutePolicy::DatabentoHistorical,
            upstream,
            "db",
            &method,
            path,
        )
    }

    #[test]
    fn every_metadata_method_is_admitted_by_get_and_post() {
        for name in DATABENTO_METADATA {
            let path = format!("/api/db/v0/metadata.{name}");
            assert_eq!(check(HOST, Method::POST, &path), Ok(()), "{path}");
            assert_eq!(check(HOST, Method::GET, &path), Ok(()), "{path}");
        }
    }

    #[test]
    fn upstream_may_carry_the_version_prefix() {
        for upstream in [
            "https://hist.databento.com/v0",
            "https://hist.databento.com/v0/",
        ] {
            assert_eq!(
                check(upstream, Method::POST, "/api/db/metadata.get_cost"),
                Ok(())
            );
            assert_eq!(
                check(upstream, Method::POST, "/api/db/v0/metadata.get_cost"),
                Err(Refusal::Path)
            );
        }
    }

    #[test]
    fn data_batch_and_unknown_paths_are_refused() {
        for path in [
            "/api/db/v0/timeseries.get_range",
            "/api/db/v0/timeseries.stream",
            "/api/db/v0/batch.submit_job",
            "/api/db/v0/batch.list_jobs",
            "/api/db/v0/batch.download",
            "/api/db/v0/symbology.resolve",
            "/api/db/v0/metadata.unknown",
            "/api/db/v0/metadata.",
            "/api/db/v0/metadata.list_datasets/extra",
            "/api/db/v0/metadata.list_datasets/",
            "/api/db/v1/metadata.list_datasets",
            "/api/db/V0/metadata.list_datasets",
            "/api/db/v0/METADATA.list_datasets",
            "/api/db/",
            "/api/db/v0",
        ] {
            assert_eq!(
                check(HOST, Method::POST, path),
                Err(Refusal::Path),
                "{path}"
            );
        }
    }

    #[test]
    fn encodings_and_dot_segments_are_refused() {
        for path in [
            "/api/db/v0/metadata.list_datasets%2F..%2Ftimeseries.get_range",
            "/api/db/v0/metadata%2Elist_datasets",
            "/api/db/v0/./metadata.list_datasets",
            "/api/db/v0//metadata.list_datasets",
            "/api/db//v0/metadata.list_datasets",
            "/api/db/v0/../v0/metadata.list_datasets",
            "/api/db/v0/metadata.list_datasets%00",
        ] {
            assert_eq!(
                check(HOST, Method::POST, path),
                Err(Refusal::Path),
                "{path}"
            );
        }
    }

    #[test]
    fn other_methods_are_refused() {
        for method in [
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::HEAD,
            Method::OPTIONS,
        ] {
            assert_eq!(
                check(HOST, method.clone(), "/api/db/v0/metadata.list_datasets"),
                Err(Refusal::Method),
                "{method}"
            );
        }
    }

    #[test]
    fn an_unrecognized_policy_refuses_everything() {
        assert_eq!(
            admit(
                RoutePolicy::Unrecognized,
                HOST,
                "db",
                &Method::GET,
                "/api/db/v0/metadata.list_datasets"
            ),
            Err(Refusal::Policy)
        );
    }

    #[test]
    fn a_path_for_another_route_or_a_bad_upstream_is_refused() {
        assert_eq!(
            check(HOST, Method::POST, "/api/other/v0/metadata.list_datasets"),
            Err(Refusal::Path)
        );
        assert_eq!(
            check(
                "not a url",
                Method::POST,
                "/api/db/v0/metadata.list_datasets"
            ),
            Err(Refusal::Path)
        );
    }
}
