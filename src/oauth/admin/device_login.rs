//! Operator device login for ChatGPT-plan (Codex) OAuth sessions (#138).
//!
//! `POST /oauth/{name}/device-login?label=` asks the provider for a
//! one-time user code and returns it with the verification URL. The
//! operator signs in on any browser; `GET /oauth/{name}/device-login/{id}`
//! polls the provider once per call. On approval the daemon exchanges
//! the authorization code itself, so no token ever transits the
//! operator's shell. The resulting refresh token goes through the same
//! create + first-exchange path as manual bootstrap.
//!
//! A session that needs reconnecting (degraded or refresh pending) is
//! replaced in place, so per-agent bindings to its label keep working.
//! A healthy session is replaced only with `replace: true`.
//!
//! Only OpenAI's device-auth dialect (the one the Codex CLI uses) is
//! implemented. Attempts live in memory and expire after 15 minutes.

use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

const MAX_WAIT: Duration = Duration::from_secs(15 * 60);
const MAX_ATTEMPTS: usize = 16;
const DEFAULT_INTERVAL: u64 = 5;
const USER_CODE_PATH: &str = "/api/accounts/deviceauth/usercode";

/// In-memory pending attempts, keyed by an unguessable id.
#[derive(Clone, Default)]
pub struct DeviceLogins(Arc<StdMutex<HashMap<String, Attempt>>>);

struct Attempt {
    name: String,
    label: String,
    replace: bool,
    issuer: String,
    client_id: String,
    device_auth_id: String,
    user_code: String,
    started: Instant,
    interval: u64,
    polling: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StartBody {
    #[serde(default)]
    pub replace: bool,
}

#[derive(Deserialize)]
struct UserCodeResp {
    device_auth_id: String,
    #[serde(alias = "usercode")]
    user_code: String,
    #[serde(default)]
    interval: Option<Value>,
}

#[derive(Deserialize)]
struct CodeResp {
    authorization_code: String,
    code_verifier: String,
}

#[derive(Deserialize)]
struct TokenResp {
    refresh_token: String,
}

/// The issuer for OpenAI's device-auth dialect, derived from the
/// registration's token URL. Supported when the token URL is OpenAI's,
/// or when the device URL names the dialect's user-code endpoint on the
/// token URL's origin (a self-hosted or test issuer). `None` otherwise.
pub(crate) fn openai_issuer(auth: &AuthSpec) -> Option<(String, String)> {
    let AuthSpec::OauthDeviceCode {
        client_id,
        device_url,
        token_url,
        ..
    } = auth
    else {
        return None;
    };
    let token = reqwest::Url::parse(token_url).ok()?;
    let issuer = token_url.strip_suffix("/oauth/token")?;
    let openai = token.scheme() == "https" && token.host_str() == Some("auth.openai.com");
    let declared = device_url.strip_suffix(USER_CODE_PATH) == Some(issuer);
    (openai || declared).then(|| (issuer.to_string(), client_id.clone()))
}

pub async fn op_oauth_device_login_start(
    State(state): State<OauthAdminState>,
    Path(name): Path<String>,
    Query(label_q): Query<LabelQuery>,
    body: Option<Json<StartBody>>,
) -> Response {
    let replace = body.map(|Json(b)| b.replace).unwrap_or(false);
    let label = label_q.label_or_default().to_string();
    guarded(&state, start(&state, name, label, replace)).await
}

pub async fn op_oauth_device_login_poll(
    State(state): State<OauthAdminState>,
    Path((name, attempt)): Path<(String, String)>,
) -> Response {
    guarded(&state, poll(&state, &name, &attempt)).await
}

async fn guarded(state: &OauthAdminState, f: impl Future<Output = Response>) -> Response {
    state.locks.owner.run(f).await.unwrap_or_else(|| {
        error_envelope(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth_error",
            "oauth_shutting_down",
            "OAuth operation stopped during daemon shutdown",
        )
    })
}

async fn start(state: &OauthAdminState, name: String, label: String, replace: bool) -> Response {
    let (issuer, client_id) = match dialect(state, &name).await {
        Ok(d) => d,
        Err(r) => return *r,
    };
    if let Err(r) = check_existing(state, &name, &label, replace).await {
        return *r;
    }
    if state.device_logins.full() {
        return error_envelope(
            StatusCode::TOO_MANY_REQUESTS,
            "conflict",
            "too_many_device_logins",
            "too many device logins are pending; finish or let one expire",
        );
    }
    let uc = match request_user_code(&issuer, &client_id).await {
        Ok(uc) => uc,
        Err(r) => return *r,
    };
    let interval = parse_interval(uc.interval.as_ref());
    let id = state.device_logins.insert(Attempt {
        name,
        label: label.clone(),
        replace,
        issuer: issuer.clone(),
        client_id,
        device_auth_id: uc.device_auth_id,
        user_code: uc.user_code.clone(),
        started: Instant::now(),
        interval,
        polling: false,
    });
    let body = json!({
        "attempt": id,
        "session_label": label,
        "verification_url": format!("{issuer}/codex/device"),
        "user_code": uc.user_code,
        "expires_in": MAX_WAIT.as_secs(),
        "interval": interval,
    });
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

async fn dialect(state: &OauthAdminState, name: &str) -> Result<(String, String), Box<Response>> {
    let registration = match state.registrations.get(name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(Box::new(error_envelope(
                StatusCode::NOT_FOUND,
                "not_found",
                "unknown_name",
                "registration not found",
            )));
        }
        Err(_) => return Err(Box::new(internal("registration read failed"))),
    };
    openai_issuer(&registration.auth).ok_or_else(|| {
        Box::new(error_envelope(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "device_login_unsupported",
            "device login supports only the OpenAI ChatGPT-plan (Codex) dialect",
        ))
    })
}

/// A healthy session is kept unless the operator asked to replace it.
/// Returns whether a row exists that must be removed before create.
async fn check_existing(
    state: &OauthAdminState,
    name: &str,
    label: &str,
    replace: bool,
) -> Result<bool, Box<Response>> {
    match state.sessions.get(&state.sealing_key, name, label).await {
        Ok(None) => Ok(false),
        Ok(Some(s)) if s.degraded || s.refresh_pending || replace => Ok(true),
        Ok(Some(_)) => Err(Box::new(error_envelope(
            StatusCode::CONFLICT,
            "conflict",
            "session_exists",
            "session is healthy; pass replace to sign it in again",
        ))),
        Err(crate::oauth::OauthSessionError::UnsupportedKind) => {
            Err(Box::new(super::status::unsupported()))
        }
        Err(_) => Err(Box::new(internal("OAuth custody read failed"))),
    }
}

async fn poll(state: &OauthAdminState, name: &str, id: &str) -> Response {
    let Some(snapshot) = state.device_logins.begin_poll(name, id) else {
        return error_envelope(
            StatusCode::NOT_FOUND,
            "not_found",
            "unknown_attempt",
            "no pending device login with that id",
        );
    };
    let Snapshot::Ready(attempt) = snapshot else {
        return pending(&snapshot);
    };
    match poll_once(&attempt).await {
        Poll::Pending => {
            state.device_logins.end_poll(id);
            pending(&Snapshot::Ready(attempt))
        }
        Poll::Failed(r) => {
            state.device_logins.remove(id);
            *r
        }
        Poll::Approved(code) => {
            state.device_logins.remove(id);
            finish(state, &attempt, code).await
        }
    }
}

fn pending(s: &Snapshot) -> Response {
    let interval = match s {
        Snapshot::Ready(a) => a.interval,
        Snapshot::Busy(i) => *i,
        Snapshot::Expired => {
            return error_envelope(
                StatusCode::GONE,
                "auth_error",
                "device_login_expired",
                "device login expired after 15 minutes; start again",
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({"status": "pending", "interval": interval})),
    )
        .into_response()
}

async fn finish(state: &OauthAdminState, a: &AttemptView, code: CodeResp) -> Response {
    let refresh = match exchange_code(a, code).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    let lock = state.locks.get(&a.name, &a.label).await;
    let _guard = lock.lock().await;
    match check_existing(state, &a.name, &a.label, a.replace).await {
        Ok(false) => {}
        Ok(true) => {
            if state.sessions.delete(&a.name, &a.label).await.is_err() {
                return internal("OAuth custody operation failed");
            }
        }
        Err(r) => return *r,
    }
    let session = match super::bootstrap::create(state, &a.name, &a.label, &refresh).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let updated = match super::bootstrap::exchange(state, &session).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let body = json!({
        "status": "complete",
        "session": session_status_json(&updated, true),
    });
    (StatusCode::OK, Json(body)).into_response()
}

fn internal(message: &str) -> Response {
    error_envelope(
        StatusCode::INTERNAL_SERVER_ERROR,
        "auth_error",
        "internal_error",
        message,
    )
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Provider failures report the status only; bodies may carry secrets.
fn upstream_failed(step: &str, status: Option<reqwest::StatusCode>) -> Box<Response> {
    let detail = status.map_or("unreachable".to_string(), |s| s.as_u16().to_string());
    Box::new(error_envelope(
        StatusCode::BAD_GATEWAY,
        "auth_error",
        "device_login_failed",
        &format!("provider {step} failed: {detail}"),
    ))
}

async fn request_user_code(issuer: &str, client_id: &str) -> Result<UserCodeResp, Box<Response>> {
    let resp = http()
        .post(format!("{issuer}{USER_CODE_PATH}"))
        .json(&json!({"client_id": client_id}))
        .send()
        .await
        .map_err(|_| upstream_failed("user-code request", None))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(upstream_failed("user-code request", Some(status)));
    }
    resp.json()
        .await
        .map_err(|_| upstream_failed("user-code request", Some(status)))
}

enum Poll {
    Pending,
    Approved(CodeResp),
    Failed(Box<Response>),
}

async fn poll_once(a: &AttemptView) -> Poll {
    let sent = http()
        .post(format!("{}/api/accounts/deviceauth/token", a.issuer))
        .json(&json!({"device_auth_id": a.device_auth_id, "user_code": a.user_code}))
        .send()
        .await;
    let Ok(resp) = sent else {
        return Poll::Pending;
    };
    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
        return Poll::Pending;
    }
    if !status.is_success() {
        return Poll::Failed(upstream_failed("device authorization", Some(status)));
    }
    match resp.json().await {
        Ok(code) => Poll::Approved(code),
        Err(_) => Poll::Failed(upstream_failed("device authorization", Some(status))),
    }
}

async fn exchange_code(a: &AttemptView, code: CodeResp) -> Result<String, Box<Response>> {
    let redirect_uri = format!("{}/deviceauth/callback", a.issuer);
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.authorization_code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", a.client_id.as_str()),
        ("code_verifier", code.code_verifier.as_str()),
    ];
    let resp = http()
        .post(format!("{}/oauth/token", a.issuer))
        .form(&form)
        .send()
        .await
        .map_err(|_| upstream_failed("code exchange", None))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(upstream_failed("code exchange", Some(status)));
    }
    resp.json::<TokenResp>()
        .await
        .map(|t| t.refresh_token)
        .map_err(|_| upstream_failed("code exchange", Some(status)))
}

/// The provider sends the interval as a string; tolerate a number too.
fn parse_interval(v: Option<&Value>) -> u64 {
    let n = match v {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    };
    n.filter(|n| (1..=60).contains(n))
        .unwrap_or(DEFAULT_INTERVAL)
}

/// What a poll may use, copied out so no lock is held across awaits.
struct AttemptView {
    name: String,
    label: String,
    replace: bool,
    issuer: String,
    client_id: String,
    device_auth_id: String,
    user_code: String,
    interval: u64,
}

enum Snapshot {
    Ready(AttemptView),
    /// Another poll for this attempt is in flight.
    Busy(u64),
    Expired,
}

impl DeviceLogins {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Attempt>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn full(&self) -> bool {
        let mut map = self.map();
        map.retain(|_, a| a.started.elapsed() < MAX_WAIT);
        map.len() >= MAX_ATTEMPTS
    }

    fn insert(&self, attempt: Attempt) -> String {
        let mut bytes = [0u8; 18];
        // An id that cannot be random must not be guessable either.
        getrandom::fill(&mut bytes).expect("OS randomness unavailable");
        let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        self.map().insert(id.clone(), attempt);
        id
    }

    fn begin_poll(&self, name: &str, id: &str) -> Option<Snapshot> {
        let mut map = self.map();
        let a = map.get_mut(id).filter(|a| a.name == name)?;
        if a.started.elapsed() >= MAX_WAIT {
            map.remove(id);
            return Some(Snapshot::Expired);
        }
        if a.polling {
            return Some(Snapshot::Busy(a.interval));
        }
        a.polling = true;
        Some(Snapshot::Ready(AttemptView {
            name: a.name.clone(),
            label: a.label.clone(),
            replace: a.replace,
            issuer: a.issuer.clone(),
            client_id: a.client_id.clone(),
            device_auth_id: a.device_auth_id.clone(),
            user_code: a.user_code.clone(),
            interval: a.interval,
        }))
    }

    fn end_poll(&self, id: &str) {
        if let Some(a) = self.map().get_mut(id) {
            a.polling = false;
        }
    }

    fn remove(&self, id: &str) {
        self.map().remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(token_url: &str) -> AuthSpec {
        device_at("https://auth.openai.com/oauth/device/code", token_url)
    }

    fn device_at(device_url: &str, token_url: &str) -> AuthSpec {
        AuthSpec::OauthDeviceCode {
            client_id: "app_x".into(),
            scopes: vec![],
            device_url: device_url.into(),
            token_url: token_url.into(),
            session_label: None,
        }
    }

    #[test]
    fn only_the_openai_issuer_is_supported() {
        assert_eq!(
            openai_issuer(&device("https://auth.openai.com/oauth/token")),
            Some(("https://auth.openai.com".into(), "app_x".into()))
        );
        for other in [
            "https://auth.openai.com.evil/oauth/token",
            "http://auth.openai.com/oauth/token",
            "https://github.com/login/oauth/access_token",
            "https://auth.openai.com/token",
        ] {
            assert_eq!(openai_issuer(&device(other)), None, "{other}");
        }
        let local = "http://127.0.0.1:9";
        assert_eq!(
            openai_issuer(&device_at(
                &format!("{local}/api/accounts/deviceauth/usercode"),
                &format!("{local}/oauth/token")
            ))
            .unwrap()
            .0,
            local
        );
        assert_eq!(
            openai_issuer(&device_at(
                "http://elsewhere/api/accounts/deviceauth/usercode",
                &format!("{local}/oauth/token")
            )),
            None,
            "the device URL must share the token URL's issuer"
        );
    }

    #[test]
    fn interval_accepts_strings_and_numbers_within_bounds() {
        assert_eq!(parse_interval(Some(&json!("7"))), 7);
        assert_eq!(parse_interval(Some(&json!(3))), 3);
        assert_eq!(parse_interval(Some(&json!("0"))), DEFAULT_INTERVAL);
        assert_eq!(parse_interval(Some(&json!(3600))), DEFAULT_INTERVAL);
        assert_eq!(parse_interval(None), DEFAULT_INTERVAL);
    }
}
