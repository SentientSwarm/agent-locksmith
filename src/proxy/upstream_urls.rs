//! Point upstream-absolute URLs in response headers back at Locksmith.
//!
//! APIs such as GitHub return absolute URLs to themselves in `Link`
//! (pagination) and `Location`. Forwarded unchanged, the agent's next
//! request bypasses Locksmith: it fails for lack of a credential, or
//! leaves the box by another path. Each URL under the route's upstream
//! base is rewritten to the same path under the agent-facing route base.

use axum::http::{HeaderMap, HeaderValue};

/// Headers whose values carry URLs back to the upstream.
const URL_HEADERS: [&str; 2] = ["link", "location"];

/// Agent-facing base, `scheme://host/api/<route>`, from the request's
/// `Host` header. `None` when the header is missing or not a plain
/// authority, in which case nothing is rewritten.
pub(super) fn agent_base(headers: &HeaderMap, tls: bool, route: &str) -> Option<String> {
    let host = headers.get(axum::http::header::HOST)?.to_str().ok()?;
    let plain = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b));
    plain.then(|| {
        format!(
            "{}://{host}/api/{route}",
            if tls { "https" } else { "http" }
        )
    })
}

/// Rewrite every URL under `upstream` in `value` to `agent_base`. A match
/// must end at a path, query or fragment boundary, so `https://api.x.com`
/// never matches `https://api.x.com.evil`. Returns `None` when unchanged.
pub(super) fn rewrite(value: &str, upstream: &str, agent_base: &str) -> Option<String> {
    let base = upstream.trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut changed = false;
    while let Some(at) = rest.find(base) {
        let after = &rest[at + base.len()..];
        let boundary = after
            .chars()
            .next()
            .is_none_or(|c| matches!(c, '/' | '?' | '#' | '>' | '"' | ',' | ';' | ' '));
        out.push_str(&rest[..at]);
        out.push_str(if boundary { agent_base } else { base });
        changed |= boundary;
        rest = after;
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// Apply [`rewrite`] to the URL-bearing headers in place.
pub(super) fn rewrite_headers(headers: &mut HeaderMap, upstream: &str, agent_base: &str) {
    for name in URL_HEADERS {
        let values: Vec<HeaderValue> = headers.get_all(name).iter().cloned().collect();
        if values.is_empty() {
            continue;
        }
        headers.remove(name);
        for value in values {
            let new = value
                .to_str()
                .ok()
                .and_then(|v| rewrite(v, upstream, agent_base))
                .and_then(|v| HeaderValue::from_str(&v).ok());
            headers.append(name, new.unwrap_or(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UP: &str = "https://api.github.com";
    const AGENT: &str = "http://10.0.0.1:9200/api/github";

    #[test]
    fn rewrites_github_pagination_links() {
        let link = r#"<https://api.github.com/organizations/1/repos?per_page=2&page=2>; rel="next", <https://api.github.com/organizations/1/repos?per_page=2&page=9>; rel="last""#;
        assert_eq!(
            rewrite(link, UP, AGENT).unwrap(),
            r#"<http://10.0.0.1:9200/api/github/organizations/1/repos?per_page=2&page=2>; rel="next", <http://10.0.0.1:9200/api/github/organizations/1/repos?per_page=2&page=9>; rel="last""#
        );
    }

    #[test]
    fn keeps_path_prefix_and_respects_boundaries() {
        let up = "https://h.example/runtime/v1/";
        let agent = "https://ls/api/m";
        assert_eq!(
            rewrite("https://h.example/runtime/v1/models?after=x", up, agent).unwrap(),
            "https://ls/api/m/models?after=x"
        );
        assert_eq!(
            rewrite("https://h.example/runtime/v1", up, agent).unwrap(),
            "https://ls/api/m"
        );
        for other in [
            "https://h.example/runtime/v10/x",
            "https://h.example.evil/runtime/v1/x",
            "https://elsewhere.example/x",
        ] {
            assert_eq!(rewrite(other, up, agent), None, "{other}");
        }
    }

    #[test]
    fn agent_base_needs_a_plain_host() {
        let mut h = HeaderMap::new();
        assert_eq!(agent_base(&h, false, "github"), None);
        h.insert("host", HeaderValue::from_static("192.168.50.13:9200"));
        assert_eq!(
            agent_base(&h, false, "github").unwrap(),
            "http://192.168.50.13:9200/api/github"
        );
        assert_eq!(
            agent_base(&h, true, "github").unwrap(),
            "https://192.168.50.13:9200/api/github"
        );
        h.insert("host", HeaderValue::from_static("evil/x?y"));
        assert_eq!(agent_base(&h, false, "github"), None);
    }

    #[test]
    fn rewrites_every_value_and_leaves_others() {
        let mut h = HeaderMap::new();
        h.append(
            "link",
            HeaderValue::from_static("<https://api.github.com/a?page=2>; rel=\"next\""),
        );
        h.append(
            "link",
            HeaderValue::from_static("<https://other.example/b>; rel=\"x\""),
        );
        h.insert(
            "location",
            HeaderValue::from_static("https://api.github.com/repos/o/r"),
        );
        h.insert(
            "etag",
            HeaderValue::from_static("\"https://api.github.com\""),
        );
        rewrite_headers(&mut h, UP, AGENT);
        let links: Vec<_> = h
            .get_all("link")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            links,
            [
                "<http://10.0.0.1:9200/api/github/a?page=2>; rel=\"next\"",
                "<https://other.example/b>; rel=\"x\""
            ]
        );
        assert_eq!(h["location"], "http://10.0.0.1:9200/api/github/repos/o/r");
        assert_eq!(
            h["etag"], "\"https://api.github.com\"",
            "only URL headers change"
        );
    }
}
