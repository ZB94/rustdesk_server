use crate::server::user::LocalPeer;
use crate::server::Response;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use database::models::user::Permission;
use jsonwebtoken::{Algorithm, Validation};

const SECRET: &[u8] = b"rustdesk api server";
const ALGORITHM: Algorithm = Algorithm::HS512;

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,
    pub iat: usize,
    #[serde(rename = "iss")]
    pub username: String,
    pub nbf: usize,
    #[serde(default)]
    pub local_peer: Option<LocalPeer>,
    pub perm: Permission,
}

impl Claims {
    #[inline]
    pub fn gen_user_token(username: String, local_peer: LocalPeer) -> String {
        Self::gen_token(username, Permission::User, Some(local_peer))
    }

    #[inline]
    pub fn gen_manage_token(username: String, perm: Permission) -> String {
        Self::gen_token(username, perm, None)
    }

    pub fn gen_token(username: String, perm: Permission, local_peer: Option<LocalPeer>) -> String {
        let current = chrono::Utc::now();
        let claims = Self {
            exp: (current + chrono::Duration::days(30)).timestamp() as usize,
            iat: current.timestamp() as usize,
            username,
            nbf: current.timestamp() as usize,
            local_peer,
            perm,
        };

        let header = jsonwebtoken::Header::new(ALGORITHM);
        let key = jsonwebtoken::EncodingKey::from_secret(SECRET);
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }
}

#[async_trait]
impl<S: Sync> FromRequestParts<S> for Claims {
    type Rejection = (StatusCode, Response<()>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        const ERROR_CODE: StatusCode = StatusCode::UNAUTHORIZED;
        const PREFIX: &str = "bearer";

        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| (ERROR_CODE, Response::error("输入token无效，请重新登录")))?;

        if let Some((prefix, token)) = header.split_once(' ') {
            if prefix.to_lowercase() == PREFIX {
                let key = jsonwebtoken::DecodingKey::from_secret(SECRET);
                let validation = Validation::new(ALGORITHM);
                if let Ok(td) = jsonwebtoken::decode(token, &key, &validation) {
                    return Ok(td.claims);
                }
            }
        }

        Err((ERROR_CODE, Response::error("token格式错误，请重新登录")))
    }
}
