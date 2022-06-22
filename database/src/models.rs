use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::Uuid;

#[derive(Debug, FromRow)]
pub struct Peer {
    pub guid: Uuid,
    pub uuid: Uuid,
    pub id: String,
    pub pk: Vec<u8>,
    pub status: Status,
    pub created_at: DateTime<Utc>,
    pub socket_addr: String,
    pub last_register_time: DateTime<Utc>,
    pub note: Option<String>,
}

#[derive(Debug, Type, Eq, PartialEq, Copy, Clone, Hash)]
#[repr(i16)]
pub enum Status {
    Client = 0,
    Normal,
    Disabled,
}
