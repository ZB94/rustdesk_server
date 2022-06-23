use database::{Database, Uuid};
use hbb_common::bytes::BytesMut;
use hbb_common::protobuf::Message;
use hbb_common::rendezvous_proto::register_pk_response::Result::{SERVER_ERROR, UUID_MISMATCH};
use hbb_common::rendezvous_proto::*;
use hbb_common::udp::FramedSocket;
use hbb_common::ResultType;
use std::net::SocketAddr;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

/// ID注册与心跳服务
pub struct UdpServer {
    db: Database,
    handle: Option<JoinHandle<()>>,
    sender: Option<UnboundedSender<(SocketAddr, RendezvousMessage)>>,
    port: u16,
}

impl UdpServer {
    pub fn new(db: Database, port: u16) -> Self {
        Self {
            db,
            handle: None,
            sender: None,
            port,
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
            let (sender, receiver) = unbounded_channel();
            self.sender = Some(sender);
            self.handle = Some(tokio::spawn(Self::run_inner(
                self.db.clone(),
                self.port,
                receiver,
            )))
        }
    }

    pub fn send_message(&self, addr: SocketAddr, msg: RendezvousMessage) {
        if let Some(sender) = &self.sender {
            let _ = sender.send((addr, msg));
        }
    }

    #[instrument(name = "udp_server", skip(db, receiver))]
    async fn run_inner(
        db: Database,
        port: u16,
        mut receiver: UnboundedReceiver<(SocketAddr, RendezvousMessage)>,
    ) {
        let address = format!("0.0.0.0:{}", port);
        let mut socket = match FramedSocket::new(&address).await {
            Ok(s) => s,
            Err(error) => {
                warn!(%error, "绑定UDP端口时出现错误");
                return;
            }
        };
        info!("正在监听UDP地址: {address}");

        loop {
            tokio::select! {
                Some((addr, msg)) = receiver.recv() => {
                    let _ = socket.send(&msg, addr).await;
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(error) =
                                Self::client_handle(db.clone(), &bytes, addr.into(), &mut socket).await
                            {
                                warn!(%error, "出现消息时出现错误");
                                return;
                            }
                        }
                        Some(Err(error)) => {
                            warn!(%error, "接收数据时发生错误");
                            return;
                        }
                        None => return,
                    }
                }
            }
        }
    }

    #[instrument(skip(db, bytes, socket))]
    async fn client_handle(
        db: Database,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            trace!("udp: {:?}", &msg_in.union);
            match msg_in.union {
                Some(rendezvous_message::Union::register_peer(rp)) if !rp.id.is_empty() => {
                    let request_pk = match db.update_addr(&rp.id, addr).await {
                        Ok(r) => r,
                        Err(error) => {
                            warn!(%error, "更新地址失败");
                            true
                        }
                    };
                    trace!("request pk: {}", request_pk);
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_peer_response(RegisterPeerResponse {
                        request_pk,
                        ..Default::default()
                    });
                    socket.send(&msg_out, addr).await?;
                }

                Some(rendezvous_message::Union::register_pk(rk))
                    if !rk.uuid.is_empty() && !rk.pk.is_empty() =>
                {
                    let uuid = match String::from_utf8_lossy(&rk.uuid).parse::<Uuid>() {
                        Ok(id) => id,
                        Err(_) => return send_rk_res(socket, addr, UUID_MISMATCH).await,
                    };
                    let id = rk.id;
                    let socket_addr = addr.to_string();
                    if id.len() < 6 {
                        return send_rk_res(socket, addr, UUID_MISMATCH).await;
                    }

                    let (changed, guid) = match db.get_peer(&id).await {
                        Ok(Some(peer)) => {
                            let addr_changed = peer.socket_addr != socket_addr;
                            if peer.uuid == uuid {
                                if addr_changed && peer.pk != rk.pk {
                                    warn!(
                                        "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                        id, socket_addr, rk.pk, peer.socket_addr, peer.pk,
                                    );
                                    return send_rk_res(socket, addr, UUID_MISMATCH).await;
                                }
                            } else {
                                warn!("Peer {} uuid mismatch: {:?} vs {:?}", id, uuid, peer.uuid);
                                return send_rk_res(socket, addr, UUID_MISMATCH).await;
                            }

                            (
                                peer.uuid != uuid || peer.pk != rk.pk || addr_changed,
                                Some(peer.guid),
                            )
                        }
                        Ok(None) => (true, None),
                        Err(error) => {
                            warn!(%error, "获取Peer失败");
                            return send_rk_res(socket, addr, SERVER_ERROR).await;
                        }
                    };
                    trace!(changed = changed, guid = ?guid, "check changed");

                    return if changed {
                        match db.update_pk(guid, &id, uuid, rk.pk, addr).await {
                            Ok(_) => {
                                send_rk_res(socket, addr, register_pk_response::Result::OK).await
                            }
                            Err(error) => {
                                warn!(%error, "更新Peer失败");
                                send_rk_res(socket, addr, SERVER_ERROR).await
                            }
                        }
                    } else {
                        send_rk_res(socket, addr, register_pk_response::Result::OK).await
                    };
                }
                Some(rendezvous_message::Union::punch_hole_request(ph)) => {
                    warn!(request=?ph, "punch_hole_request");
                }
                Some(rendezvous_message::Union::punch_hole_sent(phs)) => {
                    warn!(request=?phs, "punch_hole_sent");
                }
                Some(rendezvous_message::Union::local_addr(la)) => {
                    warn!(request=?la, "local_addr");
                }
                Some(rendezvous_message::Union::configure_update(_)) => {}
                Some(rendezvous_message::Union::software_update(_)) => {}
                _ => {}
            }
        }
        Ok(())
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}
