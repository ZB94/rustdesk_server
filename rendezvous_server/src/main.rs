#[macro_use]
extern crate tracing;

use database::Database;
use std::future::ready;
use std::time::Duration;

mod tcp_server;
mod test_nat_server;
mod udp_server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hbbs=info,warn")),
        )
        .init();

    let db = Database::new("postgresql://postgres:root@127.0.0.1/rustdesk")
        .await
        .expect("数据库初始化失败");

    let mut test_nat_server = tokio::spawn(ready(()));
    let mut udp_server = tokio::spawn(ready(()));
    let mut tcp_server = tokio::spawn(ready(()));

    loop {
        if test_nat_server.is_finished() {
            test_nat_server = tokio::spawn(test_nat_server::TestNatServer::run(21115));
        }
        if udp_server.is_finished() {
            udp_server = tokio::spawn(udp_server::UdpServer::run(db.clone(), 21116));
        }
        if tcp_server.is_finished() {
            tcp_server = tokio::spawn(tcp_server::TcpServer::run(db.clone(), 21116));
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
