use rand::Rng;
use argon2::password_hash::rand_core::SeedableRng;
use rocket_db_pools::{sqlx, Connection};
use rocket::serde::json::Json;
use rocket::{post, http::Status};
use rocket::serde::{Deserialize, Deserializer};
use base64::{Engine};
use uuid::Uuid;
use crate::DatabasePool;


// --- Request DTOs ---

/// Represents the data required to register a new user.
///
/// This struct handles the mapping from JSON input during the registration process.
/// It includes sensitive information like password hashes and cryptographic keys,
/// which are expected to be received as Base64-encoded strings and are automatically
/// decoded into byte vectors (`Vec<u8>`).
#[derive(Deserialize)]
pub struct RegisterRequest {
    /// A unique code required to allow registration.
    pub invite_code: String,
    /// The user's email address, used for identification and communication.
    pub email: String,
    /// The display name of the user.
    pub name: String,
    /// The SHA256 of the Argon2 hash of the user's password.
    /// Encoded as Base64 in JSON.
    #[serde(deserialize_with = "deserialize_base64")]
    pub password_hash: Vec<u8>,
    /// The random salt used during the password hashing process.
    /// Encoded as Base64 in JSON.
    #[serde(deserialize_with = "deserialize_base64")]
    pub password_salt: Vec<u8>,
    /// The user's public key, used for asymmetric encryption within the system.
    /// Encoded as Base64 in JSON.
    #[serde(deserialize_with = "deserialize_base64")]
    pub public_key: Vec<u8>,
    /// The user's private key, encrypted with their master key (derived from password).
    /// Encoded as Base64 in JSON.
    #[serde(deserialize_with = "deserialize_base64")]
    pub encrypted_private_key: Vec<u8>,
    /// The nonce (number used once) required to decrypt the `encrypted_private_key`.
    /// Encoded as Base64 in JSON.
    #[serde(deserialize_with = "deserialize_base64")]
    pub private_key_nonce: Vec<u8>,
    /// The Personal Team's symmetric key, wrapped (encrypted) for this specific user.
    /// This allows the user to access their own personal team's data.
    /// Encoded as Base64 in JSON.
    #[serde(deserialize_with = "deserialize_base64")]
    pub wrapped_personal_key: Vec<u8>,
    /// The nonce required to unwrap the `wrapped_personal_key`.
    /// Encoded as Base64 in JSON.
    #[serde(deserialize_with = "deserialize_base64")]
    pub personal_key_nonce: Vec<u8>,
}

/// Custom Serde deserializer to convert a Base64-encoded string into a `Vec<u8>`.
///
/// By default, Serde expects `Vec<u8>` to be a JSON array of numbers. Since our API
/// transmits binary data as Base64 strings, this helper function is used with
/// `#[serde(deserialize_with = "...")]` to perform the conversion during deserialization.
fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    // First, deserialize the input into a standard String.
    let s: String = Deserialize::deserialize(deserializer)?;
    // Use the base64 crate to decode the string using the standard engine.
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(rocket::serde::de::Error::custom)
}

/// Simple request DTO for verifying or using an invite code.
#[derive(Deserialize)]
pub struct InviteRequest {
    pub code: String,
}

// --- Routes ---

/// Signs up a new user using a one-time invite code.
///
/// This endpoint performs several atomic operations within a single database transaction:
/// 1. Validates the provided invite code and marks it as used.
/// 2. Creates a new entry in the `users` table.
/// 3. Automatically creates a "Personal Team" for the user.
/// 4. Adds the user to this team with an 'admin' role.
/// 5. Stores the user's access to the personal team's key.
///
/// Returns `201 Created` on success, `403 Forbidden` if the invite code is invalid/used,
/// or `500 Internal Server Error` if any database operation fails.
#[post("/signup", data = "<reg_data>")]
pub async fn signup(
    mut db: Connection<DatabasePool>,
    reg_data: Json<RegisterRequest>,
) -> Result<Status, Status> {

    // Start a transaction to ensure all-or-nothing success.
    // If any step fails, the transaction is rolled back and no partial data is stored.
    let mut tx = sqlx::Acquire::begin(&mut *db)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // 1. Validate and consume the invite code.
    // We attempt to update the code to 'used' in one atomic query. If zero rows are returned,
    // the code was either incorrect or already used.
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

    // 2. Create the User.
    // Insert the user's core profile and cryptographic materials into the database.
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

    // 3. Create the Personal Team.
    // Every user has a default personal team that only they belong to initially.
    let team_id = sqlx::query_scalar!(
        "INSERT INTO teams (name, is_personal) VALUES ($1, true) RETURNING id",
        format!("{}'s Personal Team", reg_data.name)
    )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // 4. Join User to Team as Admin.
    // Link the user to the newly created team.
    sqlx::query!(
        "INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'admin')",
        team_id,
        user_id
    )
        .execute(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;

    // 5. Store the wrapped Personal Team Key.
    // The client generates a personal team key, wraps it for the user's public key,
    // and sends it here for storage. This ensures only this user can unlock the team's data.
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

    // Commit the transaction to persist all changes.
    tx.commit().await.map_err(|_| Status::InternalServerError)?;

    Ok(Status::Created)
}

/// Generates a new unique invite code and stores it in the database.
///
/// This endpoint currently does not require authentication (marked as ToDo).
/// It generates a UUID v4 string and inserts it into the `invite_codes` table.
#[post("/invite")]
pub async fn generate_invite(
    mut db: Connection<DatabasePool>,
) -> Result<String, Status> {
    // Generate a unique random UUID v4 for the code.
    let new_code = Uuid::new_v4().to_string();

    // Insert the newly generated code into the database.
    sqlx::query!(
        "INSERT INTO invite_codes (code) VALUES ($1)",
        new_code
    )
        .execute(db.as_mut())
        .await
        .map_err(|_| Status::InternalServerError)?;

    // Return the generated code to the requester.
    Ok(new_code)
}


/// Fetch the salt for a given email address.
///
/// This endpoint returns the salt used for the user's password hashing.
/// If the user does not exist, it returns a deterministic random salt based on the email
/// to prevent timing attacks or user enumeration via salt requests.
#[get("/salt?<email>")]
pub async fn get_salt(mut db: Connection<DatabasePool>, email: String) -> Result<String, Status> {
    let salt = sqlx::query_scalar!(
        "SELECT password_salt FROM users WHERE email = $1",
        email
    ).fetch_optional(db.as_mut())
    .await.map_err(|_| Status::InternalServerError)?;

    match salt {
        Some(salt_bytes) => Ok(base64::engine::general_purpose::STANDARD.encode(salt_bytes)),
        None => {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            email.hash(&mut hasher);
            let seed = hasher.finish();

            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let random_salt: [u8; 16] = rng.r#gen();
            Ok(base64::engine::general_purpose::STANDARD.encode(random_salt))
        }
    }
}