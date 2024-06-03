mod user;
mod ddb;
use actix_web::{HttpServer, App, middleware::Logger, web::{self, Data}};
use ddb::DDB;
use user::services::{insert_user, login, update_user,get_user};


#[actix_web::main]
async fn main()->std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    let database = DDB::new().await;

    HttpServer::new(move||{
        let logger = Logger::default();
        let ddb_data = web::Data::new(database.clone());
        App::new()
        .app_data(ddb_data.clone())
        .service(insert_user)
        .service(login)
        .service(update_user)
        .service(get_user)
    })
    .bind(("",8000))?
    .run()
    .await
}
