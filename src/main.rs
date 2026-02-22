mod models;
pub mod routes;

#[macro_use] extern crate rocket;

use rocket::{fairing, Build, Rocket};
use rocket::fairing::AdHoc;
use rocket_db_pools::{sqlx, Database, Connection};
use rocket_db_pools::sqlx::Row;

#[derive(Database)]
#[database("postgres_db")]
struct DatabasePool(sqlx::PgPool);

#[get("/")]
async fn index(mut db: Connection<DatabasePool>) -> String {
    let result = sqlx::query("SELECT NOW()::TEXT AS current_time;").fetch_one(db.as_mut()).await;
    match result {
        Ok(row) => row.get(0),
        Err(e) => format!("Error: {}", e),
    }
}



/// Migration handler
async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    // 1. Fetch the database pool from Rocket's managed state
    if let Some(db) = DatabasePool::fetch(&rocket) {
        match sqlx::migrate!("./migrations").run(&db.0).await {
            Ok(_) => {
                println!("✅ Migrations applied successfully.");
                Ok(rocket)
            },
            Err(e) => {
                error!("❌ Migration failed: {}", e);
                Err(rocket)
            }
        }
    } else {
        error!("❌ Failed to fetch database pool for migrations.");
        Err(rocket)
    }
}



/// Application entry point
#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(DatabasePool::init())
        .attach(AdHoc::try_on_ignite("Run Migrations", run_migrations))
        .mount("/", routes![index])
        .mount("/auth", routes::auth_routes())
}