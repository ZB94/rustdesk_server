use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::Json;

#[derive(Debug, Type, Serialize, Deserialize, Eq, PartialEq, Hash, Copy, Clone)]
#[repr(i16)]
pub enum Permission {
    Admin = 0,
    User,
}

#[derive(Debug, FromRow, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub perm: Permission,
    pub disabled: bool,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct AddressBook {
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub tags: Json<Vec<String>>,
    #[serde(default)]
    pub peers: Json<Vec<Peer>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}
