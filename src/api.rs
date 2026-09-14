use std::sync::RwLock;

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Serialize;

use crate::registry::{
    DescribeFilter, RegistrationError, RegistrationRequest, Registry, Source,
};

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
            .route("/describe", web::get().to(describe))
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

/// Everything the gateway knows it can route -- static config and live
/// registrations alike -- optionally narrowed by filter params:
///
///   service=name[,name]  only these services (and the routes pointing at them)
///   route=name[,name]    only these routes
///   plugin=name[,name]   only routes guarded by these plugins
///   source=static|dynamic   config-declared or self-registered
///   path=/some/path      only routes that would match this request path
async fn describe(request: HttpRequest, registry: SharedRegistry) -> HttpResponse {
    let filter = match parse_filter(request.query_string()) {
        Ok(filter) => filter,
        Err(error) => return HttpResponse::BadRequest().json(ErrorResponse { error }),
    };

    let view = { registry.read().unwrap().describe(&filter) };
    HttpResponse::Ok().json(view)
}

/// An unrecognised filter is rejected rather than ignored: silently describing
/// everything would look like a much broader answer than the caller asked for.
fn parse_filter(query: &str) -> Result<DescribeFilter, String> {
    let pairs = web::Query::<Vec<(String, String)>>::from_query(query)
        .map_err(|e| format!("invalid query string: {e}"))?
        .into_inner();

    let mut filter = DescribeFilter::default();

    for (key, value) in pairs {
        match key.as_str() {
            "service" => filter.services.extend(split(&value)),
            "route" => filter.routes.extend(split(&value)),
            "plugin" => filter.plugins.extend(split(&value)),
            "path" => {
                if !value.starts_with('/') {
                    return Err("'path' must start with '/'".to_owned());
                }
                filter.path = Some(value);
            }
            "source" => {
                filter.source = Some(match value.as_str() {
                    "static" => Source::Static,
                    "dynamic" => Source::Dynamic,
                    other => {
                        return Err(format!(
                            "unknown source '{other}' (expected 'static' or 'dynamic')"
                        ))
                    }
                })
            }
            other => {
                return Err(format!(
                    "unknown filter '{other}' (supported: service, route, plugin, source, path)"
                ))
            }
        }
    }

    Ok(filter)
}

fn split(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
}
