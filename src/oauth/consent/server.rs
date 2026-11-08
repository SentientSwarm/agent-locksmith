//! Own the callback listener and every accepted TLS connection through join.
use super::*;
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{sync::Mutex, time::Duration};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[derive(Clone, Default)]
pub struct Supervisor(Arc<Mutex<Option<Running>>>);
struct Running {
    stop: CancellationToken,
    task: JoinHandle<()>,
    runtime: Arc<Runtime>,
}
impl Supervisor {
    /// Bind and serve the callback listener. `on_exit` runs when the serve
    /// task ends for any reason, including a panic, so the daemon can treat
    /// a listener that stops before shutdown as a failure (AGENT-217).
    pub async fn start(
        &self,
        runtime: Arc<Runtime>,
        on_exit: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let cfg = &runtime.config.callback;
        let listener = TcpListener::bind(cfg.address)
            .await
            .map_err(|_| Error("callback_bind_failed"))?;
        let cert = std::fs::read(&cfg.cert_path).map_err(|_| Error("callback_tls_failed"))?;
        let key = std::fs::read(&cfg.key_path).map_err(|_| Error("callback_tls_failed"))?;
        let certs = rustls_pemfile::certs(&mut &cert[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error("callback_tls_failed"))?;
        let key = rustls_pemfile::private_key(&mut &key[..])
            .map_err(|_| Error("callback_tls_failed"))?
            .ok_or(Error("callback_tls_failed"))?;
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| Error("callback_tls_failed"))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let router = Router::new().fallback(callback).with_state(runtime.clone());
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let rt = runtime.clone();
        let mut guard = self.0.lock().expect("callback supervisor");
        if guard.is_some() {
            return Err(Error("callback_already_started"));
        }
        let notice = OnDrop(Some(on_exit));
        let task = tokio::spawn(async move {
            let _notice = notice;
            let mut connections = JoinSet::new();
            let mut sweep = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    biased;
                    _=cancel.cancelled()=>break,
                    Some(_)=connections.join_next(), if !connections.is_empty()=>{},
                    _=sweep.tick()=>{let _=tokio::time::timeout(Duration::from_secs(5),rt.sweep()).await;},
                    incoming=listener.accept()=>{
                        // Like the other listeners, survive transient accept errors
                        // (EMFILE, ECONNABORTED): ending this task stops the daemon.
                        let (socket,_)=match incoming {
                            Ok(accepted)=>accepted,
                            Err(e)=>{
                                tracing::warn!(error=%e,"OAuth consent callback listener: accept failed");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        };
                        if connections.len()>=32 {drop(socket);continue;}
                        let acceptor=acceptor.clone();let router=router.clone();let cancel=cancel.clone();
                        connections.spawn(async move {
                            tokio::select! {
                                biased;
                                _=cancel.cancelled()=>{},
                                _=async move {
                                    let Ok(Ok(tls))=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await else {return};
                                    let service=hyper::service::service_fn(move |request| router.clone().oneshot(request));
                                    let mut builder=hyper::server::conn::http1::Builder::new();
                                    builder.keep_alive(false).max_buf_size(16384).timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5));
                                    let _=tokio::time::timeout(Duration::from_secs(55),builder.serve_connection(TokioIo::new(tls),service)).await;
                                }=>{}
                            }
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        *guard = Some(Running {
            stop,
            task,
            runtime,
        });
        Ok(())
    }
    pub async fn stop_join(&self) {
        let running = self.0.lock().expect("callback supervisor").take();
        if let Some(r) = running {
            r.stop.cancel();
            let _ = r.task.await;
            let _ = tokio::time::timeout(Duration::from_secs(5), r.runtime.shutdown()).await;
        }
    }
}
/// Runs its closure when dropped, so a task's end is reported even on panic.
struct OnDrop<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

async fn callback(State(rt): State<Arc<Runtime>>, req: Request) -> Response {
    let parsed = parameters(&rt, &req);
    let authority = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let result = match parsed {
        Ok((state, issuer, code)) => rt
            .owner
            .run(rt.callback(
                &state,
                issuer.as_deref(),
                code.as_deref(),
                authority,
                req.uri().path(),
            ))
            .await
            .unwrap_or(Err(Error("shutting_down"))),
        Err(e) => Err(e),
    };
    response(result)
}

fn response(result: Result<()>) -> Response {
    let response = if result.is_ok() {
        (
            StatusCode::OK,
            "Callback processed. Return to your operator client.",
        )
            .into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            "Callback refused. Check the operator client.",
        )
            .into_response()
    };
    api::headers(response)
}
pub(super) use super::callback_parameters::parameters;
