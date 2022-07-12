use actix_web::{
    dev::{HttpServiceFactory, ServiceFactory},
    get, web, App, HttpServer, Responder,
};
use actix_web_lab::web::{self as web_lab, Redirect};

#[get("/health")]
async fn health() -> impl Responder {
    format!("ok")
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new()
    .service(health)
    .service(load_services()))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}

fn load_services() -> Vec<Redirect> {
    vec![
        web_lab::Redirect::new("/cats", "http://cats.com"),
        web_lab::Redirect::new("/dogs", "http://dogs.com"),
    ]
}
