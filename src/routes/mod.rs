mod auth;
pub fn auth_routes() -> Vec<rocket::Route> {
    routes![auth::signup, auth::generate_invite]
}
mod credentials;