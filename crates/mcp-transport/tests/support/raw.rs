use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
#[derive(Clone)]
pub struct Reply {
    pub head: String,
    pub parts: Vec<Vec<u8>>,
    pub delay: Duration,
    pub head_delay: Duration,
    pub hold: bool,
}
impl Reply {
    pub fn body(mime: &str, bytes: Vec<u8>) -> Self {
        Self {
            head: format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nConnection: close\r\n\r\n"),
            parts: vec![bytes],
            delay: Duration::ZERO,
            head_delay: Duration::ZERO,
            hold: false,
        }
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.head = self
            .head
            .replacen("\r\n\r\n", &format!("\r\n{name}: {value}\r\n\r\n"), 1);
        self
    }
}
pub struct Server {
    pub url: String,
    pub hits: Arc<AtomicUsize>,
    pub closed: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    pub async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let c = closed.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            while let Ok((socket, _)) = listener.accept().await {
                let reply = reply.clone();
                let h = h.clone();
                let c = c.clone();
                tasks.spawn(async move {
                    let _ = serve(socket, reply, h).await;
                    c.fetch_add(1, SeqCst);
                });
                while tasks.try_join_next().is_some() {}
            }
        });
        Self {
            url,
            hits,
            closed,
            task,
        }
    }
    pub fn hits(&self) -> usize {
        self.hits.load(SeqCst)
    }
    pub async fn wait_closed(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.closed.load(SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
async fn serve(mut socket: TcpStream, reply: Reply, hits: Arc<AtomicUsize>) -> std::io::Result<()> {
    read_request(&mut socket).await?;
    hits.fetch_add(1, SeqCst);
    tokio::time::sleep(reply.head_delay).await;
    socket.write_all(reply.head.as_bytes()).await?;
    for part in reply.parts {
        tokio::time::sleep(reply.delay).await;
        socket.write_all(&part).await?;
    }
    if reply.hold {
        let mut byte = [0u8];
        let _ = socket.read(&mut byte).await?;
    }
    Ok(())
}
async fn read_request(socket: &mut TcpStream) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(socket.read_u8().await?);
        assert!(bytes.len() < 16384);
    }
    let head = String::from_utf8_lossy(&bytes);
    let length = head
        .lines()
        .find_map(|s| {
            s.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|s| s.parse::<usize>().ok())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    socket.read_exact(&mut body).await?;
    Ok(())
}
