use std::future::ready;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, get_service, post, put};
use axum::Extension;
use axum_server::tls_rustls::RustlsConfig;
use database::Database;
use serde::Serialize;
use tokio::sync::RwLock;

pub mod address_book;
pub mod jwt;
pub mod manage;
pub mod user;

pub async fn start(
    cert_path: String,
    key_path: String,
    bind: SocketAddr,
    pool: Database,
    static_dir: Option<String>,
    download_dir: Option<String>,
    server_address: ServerAddress,
) -> Result<(), axum::BoxError> {
    let config = RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .expect("tls初始化失败");

    let mut router = axum::Router::new().route(
        "/api_server.crt",
        get_service(tower_http::services::ServeFile::new(cert_path))
            .handle_error(|_| ready(StatusCode::INTERNAL_SERVER_ERROR)),
    );

    let layer_compression = static_dir.is_some() || download_dir.is_some();

    if let Some(d) = static_dir {
        debug!("static dir: {}", &d);
        let static_dir = tower_http::services::ServeDir::new(d);
        router = router
            .nest(
                "/static",
                get_service(static_dir).handle_error(|_| ready(StatusCode::INTERNAL_SERVER_ERROR)),
            )
            .route(
                "/",
                get(|| async { axum::response::Redirect::permanent("/static/") }),
            );
    }

    if let Some(d) = download_dir {
        debug!("download dir: {}", &d);
        let downloads = std::fs::read_dir(&d)
            .expect("遍历下载目录失败")
            .filter_map(|f| {
                let f = f.expect("获取下载目录文件信息失败");
                let path = f.path();
                if path.is_file() {
                    let name = path
                        .file_name()
                        .expect("获取下载目录文件名称失败")
                        .to_string_lossy()
                        .to_string();
                    Some(DownloadInfo {
                        url: format!("/download/{name}"),
                        name,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let download_dir = tower_http::services::ServeDir::new(d);
        router = router
            .nest(
                "/download",
                get_service(download_dir)
                    .handle_error(|_| ready(StatusCode::INTERNAL_SERVER_ERROR)),
            )
            .route(
                "/download_list",
                get(|dl: Extension<Arc<Vec<DownloadInfo>>>| async move {
                    let dl = (&*dl.0).clone();
                    Response::ok(serde_json::json!({ "links": dl }))
                }),
            )
            .layer(Extension(Arc::new(downloads)));
    }

    if layer_compression {
        router = router.layer(tower_http::compression::CompressionLayer::new());
    }

    router = router
        .route("/api/login", post(user::login))
        .route("/api/logout", post(user::logout))
        .route("/api/currentUser", post(user::current_user))
        .route("/api/ab", post(address_book::update_address_book))
        .route("/api/ab/get", post(address_book::get_address_book))
        .route("/manage/login", post(manage::login))
        .route("/manage/change_password", post(manage::change_password))
        .route("/manage/user", get(manage::get_users))
        .route("/manage/user", post(manage::crate_user))
        .route("/manage/user", delete(manage::delete_user))
        .route("/manage/user", put(manage::update_user))
        .route("/manage/server_address", get(manage::get_server_address))
        .route("/manage/server_address", put(manage::update_server_address))
        .layer(Extension(Arc::new(RwLock::new(server_address))))
        .layer(Extension(pool));

    axum_server::bind_rustls(bind, config)
        .serve(router.into_make_service())
        .await?;

    Ok(())
}

#[derive(Debug, Serialize, Clone)]
pub struct DownloadInfo {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerAddress {
    pub id_server: String,
    pub relay_server: String,
    pub api_server: String,
    pub pubkey: String,
}

impl ServerAddress {
    const SAVE_FILE: &'static str = "server_address.json";
    pub async fn save(&self) -> std::io::Result<()> {
        let data = serde_json::to_vec(self).unwrap();
        tokio::fs::write(Self::SAVE_FILE, data).await
    }

    pub async fn load() -> std::io::Result<Self> {
        let data = tokio::fs::read(Self::SAVE_FILE).await?;
        serde_json::from_slice(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[derive(Debug, Serialize)]
pub struct Response<T> {
    pub error: Option<String>,
    #[serde(flatten)]
    pub data: Option<T>,
}

impl<T> Response<T> {
    #[inline]
    pub fn ok(data: T) -> Self {
        Self {
            error: None,
            data: Some(data),
        }
    }

    #[inline]
    pub fn error<S: ToString>(error: S) -> Self {
        Self {
            error: Some(error.to_string()),
            data: None,
        }
    }
}

impl<T: Serialize> IntoResponse for Response<T> {
    fn into_response(self) -> axum::response::Response {
        axum::Json::into_response(axum::Json(self))
    }
}
