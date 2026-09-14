mod api;
mod config;
mod registry;

use std::sync::RwLock;
use std::time::Duration;
use std::{env, fs};

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};

use config::GatewayConfig;
use registry::{Registry, Resolution};

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    let filename = env::args().nth(1).expect("No config file provided");
    let contents = fs::read_to_string(filename).expect("Could not read config file!");
    let config: GatewayConfig = serde_yaml::from_str(&contents).expect("Invalid yaml!");

    let host = config.listen.host.to_owned();
    let proxy_port = config.listen.proxy_port;
    let registration_port = config.listen.registration_port;
    let reap_interval = Duration::from_secs(config.registration.reap_interval_seconds);

    let registry = web::Data::new(RwLock::new(Registry::from_config(&config)));

    actix_web::rt::spawn({
        let registry = registry.clone();
        async move {
            let mut ticker = actix_web::rt::time::interval(reap_interval);
            loop {
                ticker.tick().await;
                let expired = { registry.write().unwrap().reap() };
                for (service, instance_id) in expired {
                    println!("reaped expired instance {instance_id} of service {service}");
                }
            }
        }
    });

    let proxy = HttpServer::new({
        let registry = registry.clone();
        move || {
            App::new()
                .app_data(registry.clone())
                .default_service(web::to(proxy_handler))
        }
    })
    .bind((host.as_str(), proxy_port))?
    .run();

    let registration = HttpServer::new({
        let registry = registry.clone();
        move || {
            App::new()
                .app_data(registry.clone())
                .configure(api::configure)
        }
    })
    .bind((host.as_str(), registration_port))?
    .run();

    println!("proxy listening on {host}:{proxy_port}");
    println!("registration listening on {host}:{registration_port}");

    futures_util::try_join!(proxy, registration)?;
    Ok(())
}

async fn proxy_handler(req: HttpRequest, registry: web::Data<RwLock<Registry>>) -> HttpResponse {
    let resolution = { registry.read().unwrap().resolve(req.path()) };

    match resolution {
        Resolution::Resolved(resolved) => HttpResponse::Ok().body(format!(
            "RESOLVED route={} source={} service={} instance={} target={}\n",
            resolved.route,
            resolved.source,
            resolved.service.as_deref().unwrap_or("-"),
            resolved.instance.as_deref().unwrap_or("-"),
            resolved.target_url,
        )),
        Resolution::NoInstances { route, service } => HttpResponse::ServiceUnavailable().body(
            format!("no registered instances for service '{service}' (route '{route}')\n"),
        ),
        Resolution::NotFound => {
            HttpResponse::NotFound().body(format!("no route matches '{}'\n", req.path()))
        }
    }
}
