use crate::server::jwt::Claims;
use crate::server::{Response, ServerAddress};
use axum::http::StatusCode;
use axum::{Extension, Json};
use database::models::user::Permission;
use database::{Database, Error};
use std::sync::Arc;
use tokio::sync::RwLock;

#[instrument(skip(pool))]
pub async fn login(pool: Extension<Database>, Json(login): Json<Login>) -> Response<LoginResponse> {
    debug!("user login");
    match pool
        .query_user(&login.username, &login.password, login.perm)
        .await
    {
        Ok(user) => {
            if user.disabled {
                Response::error("该用户已被禁用，请联系管理员")
            } else {
                Response::ok(LoginResponse {
                    access_token: Claims::gen_manage_token(user.username, user.perm),
                    perm: user.perm,
                })
            }
        }
        Err(Error::RowNotFound) => Response::error("用户名或密码错误"),
        Err(e) => {
            warn!(error = %e, "登录时发生异常");
            Response::error("登录时发生错误，请重试或联系管理员")
        }
    }
}

#[instrument(skip(pool))]
pub async fn change_password(
    claims: Claims,
    pool: Extension<Database>,
    Json(cp): Json<ChangePassword>,
) -> Response<()> {
    debug!("user change password");
    match pool
        .update_user_password(
            &claims.username,
            &cp.old_password,
            &cp.new_password,
            claims.perm,
        )
        .await
    {
        Ok(()) => Response::ok(()),
        Err(Error::RowNotFound) => Response::error("旧密码错误"),
        Err(e) => {
            warn!(error = %e, "修改密码时发生错误");
            Response::error("修改密码时发生错误，请重试或联系管理员")
        }
    }
}

#[instrument(skip(pool))]
pub async fn get_users(claims: Claims, pool: Extension<Database>) -> (StatusCode, Response<Users>) {
    debug!("get users");
    if let Err(e) = check_admin(&claims) {
        return e;
    }

    match pool.get_users().await {
        Ok(users) => {
            debug!(users = ?&users, "用户列表");
            (
                StatusCode::OK,
                Response::ok(Users {
                    users: users
                        .into_iter()
                        .map(|u| User {
                            username: u.username,
                            perm: u.perm,
                            disabled: u.disabled,
                        })
                        .collect(),
                }),
            )
        }
        Err(e) => {
            warn!(error = %e, "获取用户列表时出现异常");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Response::error("获取用户列表时出现错误，请重试或联系管理员"),
            )
        }
    }
}

#[instrument(skip(pool))]
pub async fn crate_user(
    claims: Claims,
    pool: Extension<Database>,
    Json(user): Json<database::models::user::User>,
) -> (StatusCode, Response<()>) {
    if let Err(e) = check_admin(&claims) {
        return e;
    }

    match pool
        .create_user(&user.username, &user.password, user.perm, user.disabled)
        .await
    {
        Ok(_) => (StatusCode::OK, Response::ok(())),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Response::error("已存在相同用户名与权限用户"),
        ),
    }
}

#[instrument(skip(pool))]
pub async fn delete_user(
    claims: Claims,
    pool: Extension<Database>,
    Json(user): Json<DeleteUser>,
) -> (StatusCode, Response<()>) {
    if let Err(e) = check_admin(&claims) {
        return e;
    }

    match pool.delete_user(&user.username, user.perm).await {
        Ok(_) => (StatusCode::OK, Response::ok(())),
        Err(e) => {
            warn!(error = %e, "删除用户时发生异常");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Response::error("删除用户时发生错误，请重试或联系管理员"),
            )
        }
    }
}

#[instrument(skip(pool))]
pub async fn update_user(
    claims: Claims,
    pool: Extension<Database>,
    Json(user): Json<UpdateUser>,
) -> (StatusCode, Response<()>) {
    if let Err(e) = check_admin(&claims) {
        return e;
    }

    match pool
        .disable_user(&user.username, user.perm, user.disabled)
        .await
    {
        Ok(_) => (StatusCode::OK, Response::ok(())),
        Err(e) => {
            warn!(error = %e, "设置用户禁用状态时出现异常");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Response::error("设置用户禁用状态时出现错误，请重试或联系管理员"),
            )
        }
    }
}

#[instrument]
pub async fn get_server_address(
    _claims: Claims,
    server_address: Extension<Arc<RwLock<ServerAddress>>>,
) -> Response<ServerAddress> {
    debug!("get server address");
    Response::ok(server_address.0.read().await.clone())
}

#[instrument]
pub async fn update_server_address(
    claims: Claims,
    server_address: Extension<Arc<RwLock<ServerAddress>>>,
    Json(sa): Json<ServerAddress>,
) -> (StatusCode, Response<()>) {
    debug!("update server address");
    match check_admin(&claims) {
        Ok(_) => {
            if let Err(e) = sa.save().await {
                warn!(error = %e, "更新服务器配置失败");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Response::error("更新服务器配置失败，请重试或联系管理员"),
                )
            } else {
                *server_address.0.write().await = sa;
                (StatusCode::OK, Response::ok(()))
            }
        }
        Err(e) => e,
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub username: String,
    pub perm: Permission,
    pub disabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct DeleteUser {
    pub username: String,
    pub perm: Permission,
}

#[derive(Debug, Serialize)]
pub struct Users {
    pub users: Vec<User>,
}

#[derive(Debug, Serialize)]
pub struct User {
    pub username: String,
    pub perm: Permission,
    pub disabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ChangePassword {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
    pub perm: Permission,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub perm: Permission,
}

#[inline]
fn check_admin<T>(claims: &Claims) -> Result<(), (StatusCode, Response<T>)> {
    if claims.perm == Permission::Admin {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, Response::error("权限不足")))
    }
}
