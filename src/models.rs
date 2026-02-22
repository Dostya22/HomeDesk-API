use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// --- Enums ---

#[derive(Debug, Serialize, Deserialize, Type, PartialEq)]
#[sqlx(type_name = "team_role", rename_all = "lowercase")]
pub enum TeamRole {
    Member,
    Admin,
}

#[derive(Debug, Serialize, Deserialize, Type)]
#[sqlx(type_name = "secret_kind", rename_all = "snake_case")]
pub enum SecretKind {
    Password,
    SshKey,
}

// --- User Models ---

#[derive(Debug, Serialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip)]
    pub password_hash: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_private_key: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_nonce: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

// --- Team Models ---

#[derive(Debug, Serialize, FromRow)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub is_personal: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct TeamMember {
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub role: TeamRole,
}

#[derive(Debug, Serialize, FromRow)]
pub struct TeamKeyAccess {
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub encrypted_team_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

// --- Credential Models ---

#[derive(Debug, Serialize, FromRow)]
pub struct Credential {
    pub id: Uuid,
    pub team_id: Uuid,
    pub title: String,
    pub hostname: String,
    pub username: String,
    pub kind: SecretKind,
    pub public_key: Option<String>,
    #[serde(skip)]
    pub encrypted_secret: Vec<u8>,
    #[serde(skip)]
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
}