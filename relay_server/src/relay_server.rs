use hbb_common::protobuf::Message;
use hbb_common::rendezvous_proto::{rendezvous_message, RendezvousMessage};
use hbb_common::tcp::{new_listener, FramedStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::Span;

type PeerMap = Arc<Mutex<HashMap<String, FramedStream>>>;

/// 中继服务
pub struct RelayServer {
    port: u16,
    public_key: String,
    peers: PeerMap,
    handle: Option<JoinHandle<()>>,
}

impl RelayServer {
    pub fn new(port: u16, public_key: String) -> Self {
        Self {
            port,
            public_key,
            peers: Arc::new(Default::default()),
            handle: None,
        }
    }

    #[inline]
    pub fn running(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or_default()
    }

    pub async fn run(&mut self) {
        if !self.running() {
            self.peers.lock().await.clear();
            self.handle = Some(tokio::spawn(Self::run_inner(
                self.port,
                self.public_key.clone(),
                self.peers.clone(),
            )));
        }
    }

    #[instrument(name = "relay_server", skip(peers))]
    async fn run_inner(port: u16, public_key: String, peers: PeerMap) {
        let address = format!("0.0.0.0:{port}");
        info!("正在监听TCP地址: {address}");

        let listener = match new_listener(&address, false).await {
            Ok(l) => l,
            Err(error) => {
                warn!(%error, "监听地址时发生异常");
                return;
            }
        };

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let _ = stream.set_nodelay(true);
                    let stream = FramedStream::from(stream, addr);
                    tokio::spawn(Self::make_pair(
                        Span::current(),
                        stream,
                        public_key.clone(),
                        addr,
                        peers.clone(),
                    ));
                }
                Err(error) => {
                    warn!(%error, "接收连接时出现错误");
                    break;
                }
            }
        }
    }

    #[instrument(parent = parent_span, skip(parent_span, stream, peers, public_key))]
    async fn make_pair(
        parent_span: Span,
        mut stream: FramedStream,
        public_key: String,
        addr: SocketAddr,
        peers: PeerMap,
    ) {
        let rr = if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
            match RendezvousMessage::parse_from_bytes(&bytes) {
                Ok(msg) => match msg.union {
                    Some(rendezvous_message::Union::request_relay(rr)) => rr,
                    Some(msg) => {
                        warn!(?msg, "接收到异常消息");
                        return;
                    }
                    None => {
                        warn!("消息内容为空");
                        return;
                    }
                },
                Err(error) => {
                    warn!(%error, "接收到无法解析的数据");
                    return;
                }
            }
        } else {
            warn!("数据接收超时");
            return;
        };

        if rr.licence_key != public_key {
            warn!("公钥不匹配");
            return;
        }

        if rr.uuid.is_empty() {
            warn!("uuid为空");
            return;
        }

        let peer = peers.lock().await.remove(&rr.uuid);
        match peer {
            Some(mut peer) => {
                info!("中继请求 {} 获得来自{}的对应请求", &rr.uuid, addr);
                peer.set_raw();
                stream.set_raw();
                info!("{} 的流都处于raw状态", &rr.uuid);
                Self::relay(stream, peer).await;
                info!("中继 {} 已停止", &rr.uuid);

                // let (mut pw, mut pr) = peer.split();
                // let (mut sw, mut sr) = stream.split();
                //
                // let handle1 = tokio::spawn(pw.send_all(&mut sr));
                // let handle2 = tokio::spawn(sw.send_all(&mut pr));
                // match tokio::join!(handle1, handle2) {
                //     (Err(error), _) | (_, Err(error)) => {
                //         warn!(%error, "中继 {} 已停止", &rr.uuid);
                //     }
                //     (Ok(Err(error)), _) | (_, Ok(Err(error))) => {
                //         warn!(%error, "中继 {} 已停止", &rr.uuid);
                //     }
                //     _ => info!("中继 {} 已停止", &rr.uuid),
                // }
            }
            None => {
                info!("来自 {} 的新中继请求: {}", addr, &rr.uuid);
                peers.lock().await.insert(rr.uuid.clone(), stream);
                debug!("已缓存本次中继请求");
                tokio::time::sleep(Duration::from_secs(30)).await;
                if peers.lock().await.remove(&rr.uuid).is_some() {
                    info!("中继 {} 超过30秒未收到对应连接，已停止本次中继", &rr.uuid);
                }
            }
        }
    }

    async fn relay(mut stream: FramedStream, mut peer: FramedStream) {
        loop {
            tokio::select! {
                res = stream.next() => {
                    if let Some(Ok(bytes)) = res {
                        if peer.send_bytes(bytes.into()).await.is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                res = peer.next() => {
                    if let Some(Ok(bytes)) = res {
                        if stream.send_bytes(bytes.into()).await.is_err(){
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }
}
