#[macro_use]
extern crate tracing;

use clap::Parser;
use hbb_common::sodiumoxide::base64;
use hbb_common::sodiumoxide::base64::Variant;
use hbb_common::sodiumoxide::crypto::sign::PublicKey;
use std::time::Duration;

mod relay_server;

#[tokio::main]
async fn main() {
    let args: Args = Parser::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hbbr=info,warn")),
        )
        .init();

    let public_key = get_public_key(args.public_key);

    let mut relay_server = relay_server::RelayServer::new(args.port, public_key);

    loop {
        relay_server.run().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[derive(Debug, Parser)]
#[clap(version, author)]
struct Args {
    /// 中继服务监听端口
    #[clap(default_value = "21117")]
    pub port: u16,
    /// 公钥。如果未设置，将从运行目录的`id_ed25519.pub`文件中读取
    #[clap(long, short)]
    pub public_key: Option<String>,
}

fn get_public_key(pk: Option<String>) -> String {
    const PUBLIC_KEY_FILE: &str = "id_ed25519.pub";
    let pk =
        pk.unwrap_or_else(|| std::fs::read_to_string(PUBLIC_KEY_FILE).expect("读取公钥文件失败"));
    let pk_data = base64::decode(&pk, Variant::UrlSafe).expect("公钥格式错误");
    let _ = PublicKey::from_slice(&pk_data).expect("无效公钥");
    pk
}
