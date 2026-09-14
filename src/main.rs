mod api;
mod auth;
mod config;
mod plugins;
mod proxy;
mod registry;
mod testing;
mod websocket;

use std::sync::RwLock;
use std::time::Duration;
use std::{env, fs};

use actix_web::{web, App, HttpServer};
use awc::{Client, Connector};

use config::GatewayConfig;
use registry::Registry;
use testing::ClaimOverrides;

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    let filename = env::args().nth(1).expect("No config file provided");
    let contents = fs::read_to_string(filename).expect("Could not read config file!");
    let config: GatewayConfig = yaml_serde::from_str(&contents).expect("Invalid yaml!");

    let host = config.listen.host.to_owned();
    let proxy_port = config.listen.proxy_port;
    let registration_port = config.listen.registration_port;
    let reap_interval = Duration::from_secs(config.registration.reap_interval_seconds);
    let proxy_timeout = Duration::from_secs(config.proxy.timeout_seconds);
    let connect_timeout = Duration::from_secs(config.proxy.connect_timeout_seconds);
    let proxy_settings = config.proxy.clone();
    let userinfo_overrides = config.testing.userinfo_overrides;

    let registry = web::Data::new(RwLock::new(Registry::from_config(&config)));
    // Shared across workers rather than built per worker, so an override
    // posted to one connection is visible to the next request on any other.
    let overrides = web::Data::new(ClaimOverrides::default());

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
        let overrides = overrides.clone();
        move || {
            // One pooled client per worker thread; awc clients are not Send.
            let client = Client::builder()
                .timeout(proxy_timeout)
                .connector(Connector::new().timeout(connect_timeout))
                .disable_redirects()
                .finish();

            let mut app = App::new()
                .app_data(registry.clone())
                .app_data(overrides.clone())
                .app_data(web::Data::new(client))
                .app_data(web::Data::new(proxy_settings.clone()));

            if userinfo_overrides {
                app = app.configure(testing::configure);
            }

            app.default_service(web::to(proxy::handler))
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

    if userinfo_overrides {
        eprintln!(
            "WARNING: testing.userinfo-overrides is enabled. /testing/userinfo is mounted on the\n\
             public proxy port, and anyone who can reach it can mint any identity, including any\n\
             role. Do not run this configuration in production."
        );
    }
    println!("proxy listening on {host}:{proxy_port}");
    println!("registration listening on {host}:{registration_port}");

    futures_util::try_join!(proxy, registration)?;
    Ok(())
}
