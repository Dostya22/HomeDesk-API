# HomeDesk-API

A secure backend API for managing credentials and team secrets, built with Rust.

## Features

- **Encrypted Secret Storage**: Credentials (passwords, SSH keys) are stored encrypted at rest with nonces.
- **Team Management**: Support for users organized into teams.
- **Automatic Migrations**: Database migrations are automatically applied on startup using `sqlx`.
- **API Documentation**: Built-in serialization/deserialization with `serde` (ensuring sensitive data like encrypted secrets are never exposed in JSON responses).

## Tech Stack

- **Language**: [Rust](https://www.rust-lang.org/)
- **Web Framework**: [Rocket](https://rocket.rs/)
- **Database Wrapper**: [sqlx](https://github.com/launchbadge/sqlx) (PostgreSQL)
- **Serialization**: [serde](https://serde.rs/)
- **ID Generation**: [uuid](https://github.com/uuid-rs/uuid)

## Project Structure

- `src/main.rs`: Application entry point, database initialization, and migration handler.
- `src/models.rs`: Data models and enums (e.g., `Credential`, `SecretKind`).
- `src/routes/`: API endpoint handlers (including authentication).
- `migrations/`: SQL migration files for users, teams, and credentials.

## Getting Started

### Prerequisites

- Rust (latest stable)
- PostgreSQL

### Configuration

1. Create a `Rocket.toml` file in the root directory. You can use `Rocket.toml.template` as a starting point:
   ```bash
   cp Rocket.toml.template Rocket.toml
   ```
2. Update the `url` in the `[default.databases.postgres_db]` section with your PostgreSQL connection string.
3. The application expects a PostgreSQL database.

### Running the API

```bash
cargo run
```

The server will start on `localhost:8000` (default Rocket configuration). Migrations will run automatically on startup.

## Development Status

Current progress:
- [x] Database Schema (Users, Teams, Credentials, Invite Codes)
- [x] Models for data representation
- [x] Database migration logic
- [x] Basic routing and Authentication structure
- [ ] Credential CRUD operations
- [ ] Encryption/Decryption utility logic
