use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(super) async fn close(connections: &mut JoinSet<()>, stop: &CancellationToken) {
    stop.cancel();
    while connections.join_next().await.is_some() {}
}
