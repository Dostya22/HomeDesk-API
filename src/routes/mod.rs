mod auth;
pub fn auth_routes() -> Vec<rocket::Route> {
    routes![auth::signup, auth::generate_invite, auth::get_salt]
}
mod credentials;