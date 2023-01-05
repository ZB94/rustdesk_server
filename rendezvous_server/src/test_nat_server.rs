use hbb_common::protobuf::Message;
use hbb_common::rendezvous_proto::*;
use hbb_common::tcp::{new_listener, FramedStream};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// NAT类型测试服务
pub struct TestNatServer;

impl TestNatServer {
    #[instrument(name = "test_nat_server")]
    pub async fn run(port: u16) {
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
                    tokio::spawn(Self::client_handle(stream, addr));
                }
                Err(e) => {
                    warn!(error = %e, "接收连接时发生错误");
                    return;
                }
            }
        }
    }

    #[instrument(skip(stream))]
    async fn client_handle(stream: TcpStream, addr: SocketAddr) {
        debug!("已接收来自 {addr} 的连接");

        stream.set_nodelay(true).ok();
        let mut stream = FramedStream::from(stream, addr);

        if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
            if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                if let Some(rendezvous_message::Union::TestNatRequest(_)) = msg_in.union {
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_test_nat_response(TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    });
                    stream.send(&msg_out).await.ok();
                }
            }
        }
    }
}
