use crate::server::jwt::Claims;
use crate::server::Response;
use axum::http::StatusCode;
use axum::{Extension, Json};
use database::models::user::Permission;
use database::{Database, Error};
use uuid::Uuid;

#[instrument(skip(pool))]
pub async fn login(Json(login): Json<Login>, pool: Extension<Database>) -> Response<LoginResponse> {
    debug!("user login");
    match pool
        .query_user(&login.username, &login.password, Permission::User)
        .await
    {
        Ok(user) => {
            if user.disabled {
                Response::error("该账号已被禁用,请联系管理员")
            } else {
                let access_token = Claims::gen_user_token(login.username, login.local_peer);
                Response::ok(LoginResponse {
                    access_token,
                    user: User {
                        name: user.username,
                    },
                })
            }
        }
        Err(Error::RowNotFound) => Response::error("用户名或密码错误"),
        Err(e) => {
            warn!(login_user=?login, error=%e, "用户登录时发生异常错误");
            Response::error("服务器发生错误")
        }
    }
}

#[instrument]
pub async fn current_user(
    Json(lp): Json<LocalPeer>,
    claims: Claims,
) -> (StatusCode, Response<User>) {
    debug!("query current user");

    check_perm(&claims, Some(&lp))
        .map(|_| {
            (
                StatusCode::OK,
                Response::ok(User {
                    name: claims.username,
                }),
            )
        })
        .unwrap_or_else(|r| (StatusCode::UNAUTHORIZED, r))
}

#[instrument]
pub async fn logout(Json(_local_peer): Json<LocalPeer>, _claims: Claims) -> Response<()> {
    debug!("user logout");
    Response::ok(())
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct LocalPeer {
    pub id: String,
    #[serde(with = "ser_local_peer_uuid")]
    pub uuid: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
    #[serde(flatten)]
    pub local_peer: LocalPeer,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub user: User,
}

#[derive(Debug, Serialize)]
pub struct User {
    pub name: String,
}

mod ser_local_peer_uuid {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use uuid::Uuid;

    pub fn deserialize<'de, D>(de: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b64str = String::deserialize(de)?;
        let b64 = base64::decode(b64str).map_err(Error::custom)?;
        let uuid_str = String::from_utf8(b64).map_err(Error::custom)?;
        Uuid::parse_str(&uuid_str).map_err(Error::custom)
    }

    pub fn serialize<S>(uuid: &Uuid, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[allow(clippy::unnecessary_to_owned)]
        base64::encode(uuid.to_string()).serialize(ser)
    }
}

#[inline]
pub fn check_perm<T>(claims: &Claims, lp: Option<&LocalPeer>) -> Result<(), Response<T>> {
    if claims.perm == Permission::User
        && lp
            .map(|lp| {
                claims
                    .local_peer
                    .as_ref()
                    .map(|lp2| lp == lp2)
                    .unwrap_or_default()
            })
            .unwrap_or(true)
    {
        Ok(())
    } else {
        Err(Response::error("用户权限异常，请重新登录"))
    }
}
