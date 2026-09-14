use std::sync::RwLock;

use actix_web::{web, HttpResponse};
use serde::Serialize;

use crate::registry::{RegistrationError, RegistrationRequest, Registry};

type SharedRegistry = web::Data<RwLock<Registry>>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationResponse {
    service: String,
    instance_id: String,
    ttl_seconds: u64,
    heartbeat_interval_seconds: u64,
    heartbeat_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnknownInstanceResponse {
    error: String,
    action: &'static str,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/registry")
            .route("/services", web::post().to(register))
            .route("/services", web::get().to(list))
            .route(
                "/services/{service}/instances/{instance}",
                web::put().to(heartbeat),
            )
            .route(
                "/services/{service}/instances/{instance}",
                web::delete().to(deregister),
            ),
    );
}

async fn register(
    body: web::Json<RegistrationRequest>,
    registry: SharedRegistry,
) -> HttpResponse {
    let request = body.into_inner();
    let service = request.service.to_owned();
    let instance_id = request.instance_id.to_owned();

    let result = {
        let mut guard = registry.write().unwrap();
        guard.register(request).map(|()| guard.ttl_seconds())
    };

    match result {
        Ok(ttl_seconds) => {
            println!("registered instance {instance_id} of service {service}");
            HttpResponse::Created().json(RegistrationResponse {
                heartbeat_url: format!("/registry/services/{service}/instances/{instance_id}"),
                service,
                instance_id,
                ttl_seconds,
                heartbeat_interval_seconds: (ttl_seconds / 3).max(1),
            })
        }
        Err(RegistrationError::Invalid(error)) => {
            HttpResponse::BadRequest().json(ErrorResponse { error })
        }
        Err(RegistrationError::Conflict(error)) => {
            HttpResponse::Conflict().json(ErrorResponse { error })
        }
    }
}

async fn heartbeat(path: web::Path<(String, String)>, registry: SharedRegistry) -> HttpResponse {
    let (service, instance_id) = path.into_inner();

    let renewed = { registry.write().unwrap().heartbeat(&service, &instance_id) };

    if renewed {
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().json(UnknownInstanceResponse {
            error: format!("instance '{instance_id}' of service '{service}' is not registered"),
            action: "re-register",
        })
    }
}

async fn deregister(path: web::Path<(String, String)>, registry: SharedRegistry) -> HttpResponse {
    let (service, instance_id) = path.into_inner();

    let removed = { registry.write().unwrap().deregister(&service, &instance_id) };

    if removed {
        println!("deregistered instance {instance_id} of service {service}");
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().json(ErrorResponse {
            error: format!("instance '{instance_id}' of service '{service}' is not registered"),
        })
    }
}

async fn list(registry: SharedRegistry) -> HttpResponse {
    let services = { registry.read().unwrap().snapshot() };
    HttpResponse::Ok().json(services)
}
