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
    register_pk_response, rendezvous_message, FetchLocalAddr, RegisterPk, RegisterPkResponse,
    RendezvousMessage,
};
use hbb_common::tcp::{new_listener, FramedStream};
use hbb_common::tokio_util::codec::Framed;
use hbb_common::{timeout, AddrMangle, ResultType};
use once_cell::sync::Lazy;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::Span;

use database::Database;

type MsgSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
pub(crate) static SINK_MAP: Lazy<Arc<RwLock<HashMap<SocketAddr, MsgSink>>>> =
    Lazy::new(|| Default::default());

/// 打洞与连接服务
pub struct TcpServer;

impl TcpServer {
    #[instrument(name = "tcp_server", skip(db))]
    pub async fn run(db: Database, port: u16) {
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
                        stream,
                        addr,
                    ));
                }
                Err(e) => {
                    warn!(error = %e, "接收连接时发生错误");
                    return;
                }
            }
        }
    }

    #[instrument(parent = parent_span, skip(parent_span, db, stream))]
    async fn client_handle(parent_span: Span, db: Database, stream: TcpStream, addr: SocketAddr) {
        debug!("已接收来自 {addr} 的连接");

        stream.set_nodelay(true).ok();

        let (mut sink, mut stream) = Framed::new(stream, BytesCodec::new()).split();

        while let Ok(Some(Ok(bytes))) = timeout(30_000, stream.next()).await {
            let msg = match RendezvousMessage::parse_from_bytes(&bytes) {
                Ok(RendezvousMessage {
                    union: Some(msg), ..
                }) => msg,
                _ => continue,
            };
            trace!("tcp: {:?}", &msg);

            match msg {
                rendezvous_message::Union::register_pk(rp) => {
                    let result = Self::update_pk(db.clone(), &rp).await;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: result.into(),
                        ..Default::default()
                    });
                    if !Self::send(&mut sink, msg_out).await {
                        break;
                    }
                }

                _ => {}
            }
        }

        debug!("连接已断开");
    }

    async fn update_pk(db: Database, rp: &RegisterPk) -> register_pk_response::Result {
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

    async fn send(sink: &mut MsgSink, msg: RendezvousMessage) -> bool {
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
    }
}
