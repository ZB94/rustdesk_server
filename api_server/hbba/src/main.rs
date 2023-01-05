#[macro_use]
extern crate tracing;
#[macro_use]
extern crate serde_with;
#[macro_use]
extern crate async_trait;

use clap::Parser;
use database::Database;
use std::net::SocketAddr;

mod server;

#[tokio::main]
async fn main() {
    let args: Args = Parser::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hbba=info,warn")),
        )
        .init();

    let pool = Database::new(&args.database_url)
        .await
        .expect("数据库连接失败");

    let server_address = server::ServerAddress::load()
        .await
        .expect("服务器配置加载失败");

    server::start(
        args.cert_path,
        args.key_path,
        args.bind,
        pool,
        args.static_dir,
        args.download_dir,
        server_address,
    )
    .await
    .unwrap();
}

#[derive(Debug, Parser)]
#[command(author, version)]
pub struct Args {
    /// 数据库连接地址（仅支持postgresql）
    pub database_url: String,
    /// cert pem file path
    pub cert_path: String,
    /// key pem file path
    pub key_path: String,
    /// 服务监听地址
    #[arg(long, short, default_value = "0.0.0.0:21114")]
    pub bind: SocketAddr,
    /// UI资源目录。设置时将将指定目录的内容挂在到`/static`下
    #[arg(long, short)]
    pub static_dir: Option<String>,
    /// 设置客户端下载目录。设置时将指定目录的所有文件都改在到`/download`下
    #[arg(long, short)]
    pub download_dir: Option<String>,
}
