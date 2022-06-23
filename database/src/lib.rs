#[macro_use]
extern crate sqlx;

use std::net::SocketAddr;

use sqlx::migrate::Migrator;
pub use sqlx::types::Uuid;
use sqlx::{Error, PgPool};

use crate::models::{Peer, Status};

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
