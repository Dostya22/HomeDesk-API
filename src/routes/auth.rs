use rocket_db_pools::{sqlx, Connection};
use rocket::serde::json::Json;
use rocket::{post, http::Status};
use rocket::serde::Deserialize;
use uuid::Uuid;
use crate::DatabasePool;


// --- Request DTOs ---

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub invite_code: String,
    pub email: String,
    pub name: String,
    pub password_hash: Vec<u8>,
    pub password_salt: Vec<u8>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    // Wrapped Personal Team Key data
    pub wrapped_personal_key: Vec<u8>,
    pub personal_key_nonce: Vec<u8>,
}

#[derive(Deserialize)]
pub struct InviteRequest {
    pub code: String,
}

// --- Routes ---

/// Signs up a new user using a one-time invite code.
/// This creates the user and their mandatory personal team in a single transaction.
#[post("/signup", data = "<reg_data>")]
pub async fn signup(
    mut db: Connection<DatabasePool>,
    reg_data: Json<RegisterRequest>,
) -> Result<Status, Status> {

    // Start a transaction to ensure all-or-nothing success
    let mut tx = sqlx::Acquire::begin(&mut *db)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // 1. Validate and consume the invite code
    let invite = sqlx::query!(
        "UPDATE invite_codes SET is_used = true WHERE code = $1 AND is_used = false RETURNING id",
        reg_data.invite_code
    )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;

    if invite.is_none() {
        return Err(Status::Forbidden);
    }

    // 2. Create the User
    let user_id = sqlx::query_scalar!(
        "INSERT INTO users (email, name, password_hash, password_salt, public_key, encrypted_private_key, private_key_nonce)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        reg_data.email,
        reg_data.name,
        reg_data.password_hash,
        reg_data.password_salt,
        reg_data.public_key,
        reg_data.encrypted_private_key,
        reg_data.private_key_nonce
    )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // 3. Create the Personal Team
    let team_id = sqlx::query_scalar!(
        "INSERT INTO teams (name, is_personal) VALUES ($1, true) RETURNING id",
        format!("{}'s Personal Team", reg_data.name)
    )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // 4. Join User to Team as Admin
    sqlx::query!(
        "INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'admin')",
        team_id,
        user_id
    )
        .execute(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // 5. Store the wrapped Personal Team Key
    sqlx::query!(
        "INSERT INTO team_key_access (team_id, user_id, encrypted_team_key, nonce) VALUES ($1, $2, $3, $4)",
        team_id,
        user_id,
        reg_data.wrapped_personal_key,
        reg_data.personal_key_nonce
    )
        .execute(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // Commit the transaction
    tx.commit().await.map_err(|_| Status::InternalServerError)?;

    Ok(Status::Created)
}

/// Generates a new invite code and returns it to the user. (ToDo add authentication)
#[post("/invite")]
pub async fn generate_invite(
    mut db: Connection<DatabasePool>,
) -> Result<String, Status> {
    // Generate a unique random string for the code
    let new_code = Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO invite_codes (code) VALUES ($1)",
        new_code
    )
        .execute(db.as_mut())
        .await
        .map_err(|_| Status::InternalServerError)?;

    // Return the code to the user
    Ok(new_code)
}