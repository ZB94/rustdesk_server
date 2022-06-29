#[macro_use]
extern crate sqlx;
#[cfg(feature = "peer")]
use std::net::SocketAddr;

pub use sqlx::error;
use sqlx::migrate::Migrator;
pub use sqlx::types::Uuid;
pub use sqlx::Error;
use sqlx::PgPool;

#[cfg(feature = "peer")]
use models::peer::{Peer, Status};

#[cfg(feature = "user")]
use crate::models::user::{self, AddressBook, Permission, User};

pub mod models;

static MIGRATOR: Migrator = migrate!();

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(url: &str) -> Result<Self, Error> {
        let pool = PgPool::connect(url).await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }
}

/// 心跳/中继服务相关
#[cfg(feature = "peer")]
impl Database {
    pub async fn get_peer(&self, id: &str) -> Result<Option<Peer>, Error> {
        sqlx::query_as("select * from peer where id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn update_addr(&self, id: &str, socket_addr: SocketAddr) -> Result<bool, Error> {
        match sqlx::query_as::<_, (Vec<u8>, String)>("select pk, socket_addr from peer where id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
        {
            Some((pk, old_socket_addr)) => {
                let socket_addr = socket_addr.to_string();
                sqlx::query(
                    "update peer set last_register_time=current_timestamp, socket_addr=$1 where id=$2",
                )
                .bind(&socket_addr)
                .bind(id)
                .execute(&self.pool)
                .await?;
                Ok(pk.is_empty() || old_socket_addr != socket_addr)
            }
            None => Ok(true),
        }
    }

    pub async fn update_pk(
        &self,
        guid: Option<Uuid>,
        id: &str,
        uuid: Uuid,
        pk: Vec<u8>,
        socket_addr: SocketAddr,
    ) -> Result<(), Error> {
        let socket_addr = socket_addr.to_string();
        if let Some(guid) = guid {
            sqlx::query("update peer set id=$1, uuid=$2, pk=$3, socket_addr=$4, last_register_time=current_timestamp where guid=$5")
                .bind(id)
                .bind(uuid)
                .bind(pk)
                .bind(socket_addr)
                .bind(guid)
                .execute(&self.pool)
                .await
                .map(|_|())
        } else {
            let guid = Uuid::from_u128(uuid::Uuid::new_v4().as_u128());
            sqlx::query("insert into peer values($1, $2, $3, $4, $5, current_timestamp, $6, current_timestamp, null)")
                .bind(guid)
                .bind(uuid)
                .bind(id)
                .bind(pk)
                .bind(Status::Client)
                .bind(socket_addr)
                .execute(&self.pool)
                .await
                .map(|_|())
        }
    }
}

/// 用户相关
#[cfg(feature = "user")]
impl Database {
    pub async fn query_user(
        &self,
        username: &str,
        password: &str,
        perm: Permission,
    ) -> Result<User, Error> {
        sqlx::query_as(r#"select * from "user" where username=$1 and password=$2 and perm=$3"#)
            .bind(username)
            .bind(password)
            .bind(perm)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        perm: Permission,
        disabled: bool,
    ) -> Result<(), Error> {
        sqlx::query(r#"insert into "user" values ($1, $2, $3, $4);"#)
            .bind(username)
            .bind(password)
            .bind(perm)
            .bind(disabled)
            .execute(&self.pool)
            .await?;

        if perm == Permission::User {
            let _ = sqlx::query("insert into address_book(username) values ($1)")
                .bind(username)
                .execute(&self.pool)
                .await;
        }

        Ok(())
    }

    pub async fn delete_user(&self, username: &str, perm: Permission) -> Result<(), Error> {
        let mut tx = self.pool.begin().await?;

        if perm == Permission::User {
            sqlx::query("delete from address_book where username = $1")
                .bind(username)
                .execute(&mut tx)
                .await?;
        }
        sqlx::query(r#"delete from "user" where username = $1 and perm = $2"#)
            .bind(username)
            .bind(perm)
            .execute(&mut tx)
            .await?;

        tx.commit().await
    }

    pub async fn update_user_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
        perm: Permission,
    ) -> Result<(), Error> {
        sqlx::query(
            r#"update "user" set password=$1 where username=$2 and password=$3 and perm=$4"#,
        )
        .bind(new_password)
        .bind(username)
        .bind(old_password)
        .bind(perm)
        .execute(&self.pool)
        .await
        .and_then(|r| {
            if r.rows_affected() == 1 {
                Ok(())
            } else {
                Err(sqlx::Error::RowNotFound)
            }
        })
    }

    pub async fn get_users(&self) -> Result<Vec<User>, Error> {
        sqlx::query_as(r#"select * from "user""#)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn disable_user(
        &self,
        username: &str,
        perm: Permission,
        disabled: bool,
    ) -> Result<(), Error> {
        sqlx::query(r#"update "user" set disabled = $1 where username = $2 and perm = $3"#)
            .bind(disabled)
            .bind(username)
            .bind(perm)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }
}

/// 地址簿相关
#[cfg(feature = "user")]
impl Database {
    pub async fn get_address_book(&self, username: &str) -> Result<AddressBook, Error> {
        sqlx::query_as("select updated_at, tags, peers from address_book where username = $1")
            .bind(username)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn update_address_book(
        &self,
        username: &str,
        tags: &[String],
        peers: &[user::Peer],
    ) -> Result<(), Error> {
        sqlx::query("update address_book set updated_at=current_timestamp, tags=$1, peers=$2 where username=$3")
            .bind(sqlx::types::Json(tags))
            .bind(sqlx::types::Json(peers))
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
