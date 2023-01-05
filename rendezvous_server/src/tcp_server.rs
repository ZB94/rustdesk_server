use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use hbb_common::bytes::Bytes;
use hbb_common::bytes_codec::BytesCodec;
use hbb_common::futures::stream::SplitSink;
use hbb_common::futures::SinkExt;
use hbb_common::futures_util::StreamExt;
use hbb_common::protobuf::Message;
use hbb_common::rendezvous_proto::{
    punch_hole_response, register_pk_response, rendezvous_message, FetchLocalAddr,
    PunchHoleResponse, RegisterPk, RegisterPkResponse, RendezvousMessage, TestNatResponse,
};
use hbb_common::sodiumoxide::base64;
use hbb_common::sodiumoxide::crypto::sign;
use hbb_common::sodiumoxide::crypto::sign::SecretKey;
use hbb_common::tcp::new_listener;
use hbb_common::tokio_util::codec::Framed;
use hbb_common::{timeout, AddrMangle};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::Span;

use database::Database;

use crate::Variant;

pub type MessageSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
pub type MessageSinkMap = Arc<RwLock<HashMap<SocketAddr, MessageSink>>>;

/// 打洞与连接服务
pub struct TcpServer {
    db: Database,
    map: MessageSinkMap,
    port: u16,
    handle: Option<JoinHandle<()>>,
    receiver: Option<UnboundedReceiver<(SocketAddr, RendezvousMessage)>>,
    secret_key: SecretKey,
}

impl TcpServer {
    pub fn new(db: Database, port: u16, secret_key: SecretKey) -> Self {
        Self {
            db,
            map: Arc::new(Default::default()),
            port,
            handle: None,
            receiver: None,
            secret_key,
        }
    }

    pub async fn run(&mut self) {
        if !self.running() {
            self.map.write().await.clear();
            let (sender, receiver) = unbounded_channel();
            self.receiver = Some(receiver);
            self.handle = Some(tokio::spawn(Self::run_inner(
                self.db.clone(),
                self.map.clone(),
                sender,
                self.port,
                self.secret_key.clone(),
            )));
        }
    }

    #[inline]
    pub fn running(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or_default()
    }

    pub async fn get_udp_message(&mut self) -> Vec<(SocketAddr, RendezvousMessage)> {
        let mut ret = vec![];
        if let Some(r) = &mut self.receiver {
            while let Ok(a) = r.try_recv() {
                ret.push(a);
            }
        }
        ret
    }

    #[instrument(name = "tcp_server", skip(db, map, sender))]
    async fn run_inner(
        db: Database,
        map: MessageSinkMap,
        sender: UnboundedSender<(SocketAddr, RendezvousMessage)>,
        port: u16,
        secret_key: SecretKey,
    ) {
        let address = format!("0.0.0.0:{}", port);
        let listener = match new_listener(&address, false).await {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "监听端口时发生错误");
                return;
            }
        };
        info!("正在监听TCP地址: {address}");
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    tokio::spawn(Self::client_handle(
                        Span::current(),
                        db.clone(),
                        map.clone(),
                        sender.clone(),
                        stream,
                        addr,
                        secret_key.clone(),
                    ));
                }
                Err(e) => {
                    warn!(error = %e, "接收连接时发生错误");
                    return;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(parent = parent_span, skip(parent_span, db, map, stream, sender, secret_key))]
    async fn client_handle(
        parent_span: Span,
        db: Database,
        map: MessageSinkMap,
        sender: UnboundedSender<(SocketAddr, RendezvousMessage)>,
        stream: TcpStream,
        addr: SocketAddr,
        secret_key: SecretKey,
    ) {
        debug!("已接收来自 {addr} 的连接");

        stream.set_nodelay(true).ok();

        let (sink, mut stream) = Framed::new(stream, BytesCodec::new()).split();
        map.write().await.insert(addr, sink);

        macro_rules! send {
            ($msg: expr) => {
                if !Self::send(&map, addr, $msg).await {
                    break;
                }
            };
        }

        while let Ok(Some(Ok(bytes))) = timeout(30_000, stream.next()).await {
            let msg = match RendezvousMessage::parse_from_bytes(&bytes) {
                Ok(RendezvousMessage {
                    union: Some(msg), ..
                }) => msg,
                _ => continue,
            };
            trace!("tcp: {:?}", &msg);

            let public_key = base64::encode(secret_key.public_key().0, Variant::UrlSafe);

            match msg {
                rendezvous_message::Union::register_pk(rp) => {
                    let result = Self::update_id(db.clone(), &rp).await;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: result.into(),
                        ..Default::default()
                    });
                    send!(msg_out);
                }
                rendezvous_message::Union::punch_hole_request(phr) => {
                    if phr.licence_key != public_key {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_punch_hole_response(PunchHoleResponse {
                            failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                            ..Default::default()
                        });
                        send!(msg_out);
                        continue;
                    }

                    match db.get_peer(&phr.id).await {
                        Ok(Some(peer)) => {
                            let now = chrono::Utc::now();
                            if now - peer.last_register_time > chrono::Duration::seconds(30) {
                                let mut msg_out = RendezvousMessage::new();
                                msg_out.set_punch_hole_response(PunchHoleResponse {
                                    failure: punch_hole_response::Failure::OFFLINE.into(),
                                    ..Default::default()
                                });
                                send!(msg_out);
                                continue;
                            }

                            let peer_addr: SocketAddr = peer.socket_addr.parse().unwrap();
                            // if addr.ip() != peer_addr.ip() {
                            //     let mut msg_out = RendezvousMessage::new();
                            //     msg_out.set_punch_hole(PunchHole {
                            //         socket_addr: AddrMangle::encode(addr),
                            //         nat_type: phr.nat_type,
                            //         ..Default::default()
                            //     });
                            //     let _ = sender.send((peer_addr, msg_out));
                            // } else {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_fetch_local_addr(FetchLocalAddr {
                                socket_addr: AddrMangle::encode(addr),
                                ..Default::default()
                            });
                            let _ = sender.send((peer_addr, msg_out));
                            // }
                        }
                        Ok(None) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_punch_hole_response(PunchHoleResponse {
                                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                                ..Default::default()
                            });
                            send!(msg_out);
                        }
                        Err(error) => {
                            warn!(%error, "获取打洞对象信息失败");
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_punch_hole_response(PunchHoleResponse {
                                other_failure: "服务出错".to_string(),
                                ..Default::default()
                            });
                            send!(msg_out);
                        }
                    }
                }
                rendezvous_message::Union::local_addr(la) => {
                    let socket_addr = AddrMangle::decode(&la.socket_addr);
                    let local_addr = AddrMangle::decode(&la.local_addr);
                    let id = &la.id;
                    debug!(%addr, %socket_addr, %local_addr, %id, "local addr");

                    let mut msg_out = RendezvousMessage::new();
                    let mut p = PunchHoleResponse {
                        socket_addr: la.local_addr,
                        pk: Self::get_pk(db.clone(), &la.version, la.id, &secret_key).await,
                        relay_server: la.relay_server,
                        ..Default::default()
                    };
                    p.set_is_local(true);
                    msg_out.set_punch_hole_response(p);
                    Self::send(&map, socket_addr, msg_out).await;
                }
                rendezvous_message::Union::relay_response(mut rr) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.get_id();
                    if !id.is_empty() {
                        let pk = Self::get_pk(db.clone(), &rr.version, id.to_string(), &secret_key)
                            .await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_relay_response(rr);
                    Self::send(&map, addr_b, msg_out).await;
                }
                rendezvous_message::Union::request_relay(mut rr) => match db.get_peer(&rr.id).await
                {
                    Ok(Some(peer)) => {
                        let mut msg_out = RendezvousMessage::new();
                        rr.socket_addr = AddrMangle::encode(addr);
                        msg_out.set_request_relay(rr);
                        let peer_addr = peer.socket_addr.parse().unwrap();
                        let _ = sender.send((peer_addr, msg_out));
                    }
                    Ok(None) => warn!(message = ?rr, "请求中继到不存在Peer"),
                    Err(error) => warn!(message = ?rr, %error, "获取Peer时出现错误"),
                },
                rendezvous_message::Union::punch_hole_sent(phs) => {
                    let addr_a = AddrMangle::decode(&phs.socket_addr);
                    let mut msg_out = RendezvousMessage::new();
                    let mut p = PunchHoleResponse {
                        socket_addr: AddrMangle::encode(addr),
                        pk: Self::get_pk(db.clone(), &phs.version, phs.id, &secret_key).await,
                        relay_server: phs.relay_server.clone(),
                        ..Default::default()
                    };
                    if let Ok(t) = phs.nat_type.enum_value() {
                        p.set_nat_type(t);
                    }
                    msg_out.set_punch_hole_response(p);
                    let _ = Self::send(&map, addr_a, msg_out).await;
                }
                rendezvous_message::Union::test_nat_request(_) => {
                    debug!("test nat request");
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_test_nat_response(TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    });
                    send!(msg_out);
                }
                _ => {
                    warn!(?msg, "未解析的TCP消息");
                }
            }
        }

        map.write().await.remove(&addr);
        debug!("连接已断开");
    }

    async fn update_id(db: Database, rp: &RegisterPk) -> register_pk_response::Result {
        match db.get_peer(&rp.id).await {
            Ok(None) => match db.get_peer(&rp.old_id).await {
                Ok(Some(peer)) => match String::from_utf8_lossy(&rp.uuid).parse() {
                    Ok(uuid) => match db
                        .update_pk(
                            Some(peer.guid),
                            &rp.id,
                            uuid,
                            peer.pk,
                            peer.socket_addr.parse().unwrap(),
                        )
                        .await
                    {
                        Ok(_) => {
                            info!("Peer(ID={})的ID修改为{}", &rp.old_id, &rp.id);
                            register_pk_response::Result::OK
                        }
                        Err(error) => {
                            warn!(%error, "更新ID失败");
                            register_pk_response::Result::SERVER_ERROR
                        }
                    },
                    Err(error) => {
                        warn!(%error,"更新ID时输入的UUID无效");
                        register_pk_response::Result::UUID_MISMATCH
                    }
                },
                Ok(None) => {
                    warn!(%rp.old_id, "更新ID时未找到对应的Peer");
                    register_pk_response::Result::SERVER_ERROR
                }
                Err(error) => {
                    warn!(%error, "更新ID时获取对应的Peer失败");
                    register_pk_response::Result::SERVER_ERROR
                }
            },
            Ok(Some(_)) => register_pk_response::Result::ID_EXISTS,
            Err(error) => {
                warn!(%error, "检查新ID是否已存在时出现错误");
                register_pk_response::Result::SERVER_ERROR
            }
        }
    }

    async fn send(map: &MessageSinkMap, socket_addr: SocketAddr, msg: RendezvousMessage) -> bool {
        if let Some(sink) = map.write().await.get_mut(&socket_addr) {
            match msg.write_to_bytes() {
                Ok(bytes) => match sink.send(bytes.into()).await {
                    Ok(_) => true,
                    Err(error) => {
                        warn!(%error, "发送响应消息失败");
                        false
                    }
                },
                Err(error) => {
                    warn!(%error, "无法将消息转为数据");
                    false
                }
            }
        } else {
            false
        }
    }

    #[inline]
    async fn get_pk(db: Database, version: &str, id: String, sk: &SecretKey) -> Vec<u8> {
        if version.is_empty() {
            Vec::new()
        } else {
            match db.get_peer(&id).await {
                Ok(Some(peer)) => sign::sign(
                    &hbb_common::message_proto::IdPk {
                        id,
                        pk: peer.pk,
                        ..Default::default()
                    }
                    .write_to_bytes()
                    .unwrap_or_default(),
                    sk,
                ),
                _ => Vec::new(),
            }
        }
    }
}
