#[macro_use]
extern crate tracing;

use crate::base64::Variant;
use database::Database;
use hbb_common::sodiumoxide::base64;
use hbb_common::sodiumoxide::crypto::sign;
use hbb_common::sodiumoxide::crypto::sign::SecretKey;
use std::future::ready;
use std::io::{Read, Write};
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

    let (_pk, sk) = gen_sk();

    let db = Database::new("postgresql://postgres:root@127.0.0.1/rustdesk")
        .await
        .expect("数据库初始化失败");

    let mut test_nat_server = tokio::spawn(ready(()));
    let mut udp_server = udp_server::UdpServer::new(db.clone(), 21116);
    let mut tcp_server = tcp_server::TcpServer::new(db.clone(), 21116, true, sk);

    loop {
        if test_nat_server.is_finished() {
            test_nat_server = tokio::spawn(test_nat_server::TestNatServer::run(21115));
        }

        tcp_server.run().await;
        udp_server.run().await;

        for (addr, msg) in tcp_server.get_udp_message().await {
            udp_server.send_message(addr, msg);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn gen_sk() -> (String, SecretKey) {
    let sk_file = "id_ed25519";
    if let Ok(mut file) = std::fs::File::open(sk_file) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            let sk = base64::decode(&contents, Variant::UrlSafe).unwrap_or_default();
            if sk.len() == sign::SECRETKEYBYTES {
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                let pk = base64::encode(&tmp[sign::SECRETKEYBYTES / 2..], Variant::UrlSafe);
                info!("Private key comes from {}", sk_file);
                return (pk, SecretKey(tmp));
            }
        }
    } else {
        let (pk, sk) = sign::gen_keypair();
        let pub_file = format!("{}.pub", sk_file);
        if let Ok(mut f) = std::fs::File::create(&pub_file) {
            f.write_all(base64::encode(pk, Variant::UrlSafe).as_bytes())
                .ok();
            if let Ok(mut f) = std::fs::File::create(sk_file) {
                let s = base64::encode(&sk, Variant::UrlSafe);
                if f.write_all(s.as_bytes()).is_ok() {
                    info!("Private/public key written to {}/{}", sk_file, pub_file);
                    debug!("Public key: {:?}", pk);
                    return (base64::encode(pk, Variant::UrlSafe), sk);
                }
            }
        }
    }
    panic!("无法读取或生成密钥");
}
