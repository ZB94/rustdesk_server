#[macro_use]
extern crate tracing;

use clap::Parser;
use database::Database;
use hbb_common::sodiumoxide::base64;
use hbb_common::sodiumoxide::base64::Variant;
use hbb_common::sodiumoxide::crypto::sign;
use hbb_common::sodiumoxide::crypto::sign::SecretKey;
use std::future::ready;
use std::time::Duration;

mod tcp_server;
mod test_nat_server;
mod udp_server;

#[tokio::main]
async fn main() {
    let args: Args = Parser::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hbbs=info,warn")),
        )
        .init();

    let secret_key = get_or_gen_sk(args.secret_key);

    let db = Database::new(&args.database_url)
        .await
        .expect("数据库初始化失败");

    let port = args.port;
    let nat_port = args.nat_server_port.unwrap_or(port - 1);
    let mut test_nat_server = tokio::spawn(ready(()));
    let mut udp_server = udp_server::UdpServer::new(db.clone(), port);
    let mut tcp_server = tcp_server::TcpServer::new(db.clone(), port, secret_key);

    loop {
        if test_nat_server.is_finished() {
            test_nat_server = tokio::spawn(test_nat_server::TestNatServer::run(nat_port));
        }

        tcp_server.run().await;
        udp_server.run().await;

        for (addr, msg) in tcp_server.get_udp_message().await {
            udp_server.send_message(addr, msg);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[derive(Debug, Parser)]
#[command(version, author)]
struct Args {
    /// 数据库连接地址（仅支持postgresql）
    pub database_url: String,
    /// ID服务器监听端口
    #[arg(default_value = "21116")]
    pub port: u16,
    /// NAT类型测试服务鉴定端口。如果未设置，值为`port - 1`
    #[arg(long, short)]
    pub nat_server_port: Option<u16>,
    /// 安全密钥。如果未设置将从运行目录的`id_ed25519`文件中读取，如果文件不存在则自动生成。
    ///
    /// 如果手动指定安全密钥或触发自动生成，则密钥和公钥将会自动保存于`id_ed25519`和`id_ed25519.pub`文件中
    #[arg(long, short)]
    pub secret_key: Option<String>,
}

pub fn get_or_gen_sk(secret_key: Option<String>) -> SecretKey {
    const VARIANT: Variant = Variant::UrlSafe;
    const SECRET_KEY_FILE: &str = "id_ed25519";
    const PUBLIC_KEY_FILE: &str = "id_ed25519.pub";

    let (save, sk) = secret_key
        .map(|sk| (true, sk))
        .or_else(|| {
            std::fs::read_to_string(SECRET_KEY_FILE)
                .ok()
                .map(|sk| (false, sk))
        })
        .map(|(save, sk)| {
            let sk = base64::decode(sk, VARIANT).expect("输入的密钥格式错误");
            let sk = SecretKey::from_slice(&sk).expect("输入的密钥无效");
            (save, sk)
        })
        .unwrap_or_else(|| {
            let (_, sk) = sign::gen_keypair();
            (true, sk)
        });

    if save {
        let pk = base64::encode(sk.public_key(), VARIANT);
        let sk_str = base64::encode(&sk, VARIANT);
        std::fs::write(SECRET_KEY_FILE, sk_str).expect("密钥保存失败");
        std::fs::write(PUBLIC_KEY_FILE, pk).expect("公钥保存失败");
        info!("已将密钥/公钥保存到 {SECRET_KEY_FILE}/{PUBLIC_KEY_FILE}");
    }

    sk
}
