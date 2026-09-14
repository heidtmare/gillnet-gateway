use std::sync::RwLock;

use actix_web::body::SizedStream;
use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use actix_web::{web, HttpRequest, HttpResponse};
use awc::error::SendRequestError;
use awc::{Client, ClientResponse};

use crate::auth::{self, AuthOutcome};
use crate::config::ProxyConfig;
use crate::plugins::wasm::{self, FilterOutcome, StopResponse, WasmFilter};
use crate::registry::{Registry, Resolution, Resolved};
use crate::websocket;

/// Headers that apply to a single transport hop and must never be relayed.
/// RFC 9110 section 7.6.1, plus the non-standard `proxy-connection`.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub async fn handler(
    req: HttpRequest,
    payload: web::Payload,
    registry: web::Data<RwLock<Registry>>,
    client: web::Data<Client>,
    settings: web::Data<ProxyConfig>,
) -> HttpResponse {
    let resolution = { registry.read().unwrap().resolve(req.path()) };

    let resolved = match resolution {
        Resolution::Resolved(resolved) => resolved,
        Resolution::NoInstances { route, service } => {
            return HttpResponse::ServiceUnavailable().body(format!(
                "no registered instances for service '{service}' (route '{route}')\n"
            ))
        }
        Resolution::NotFound => {
            return HttpResponse::NotFound().body(format!("no route matches '{}'\n", req.path()))
        }
    };

    let target = match req.query_string() {
        "" => resolved.target_url.to_owned(),
        query => format!("{}?{}", resolved.target_url, query),
    };

    let mut identity = match auth::enforce(&resolved.guards, req.headers(), &client).await {
        AuthOutcome::Allowed(headers) => headers,
        AuthOutcome::Unauthorized(message) => {
            return HttpResponse::Unauthorized()
                .insert_header(("www-authenticate", "Bearer"))
                .body(format!("{message}\n"))
        }
        AuthOutcome::Forbidden(message) => {
            return HttpResponse::Forbidden().body(format!("{message}\n"))
        }
        // The token may well be valid; we simply cannot confirm it, so refuse
        // rather than guess.
        AuthOutcome::Unavailable(message) => {
            return HttpResponse::ServiceUnavailable().body(format!("{message}\n"))
        }
    };
    // Headers the client's own copy of must not reach the upstream: the
    // identity headers we derive from verified claims, which a client could
    // otherwise send itself to impersonate a user to a backend that trusts
    // them; and, unless the route opted into forward-token, the credential the
    // guards just consumed, which the backend has no need to hold.
    let mut blocked = auth::injected_header_names(&resolved.guards);
    if !resolved.forward_token {
        blocked.extend(auth::credential_header_names(&resolved.guards));
    }

    // WebAssembly filters run only once the guards have passed, so a module
    // never sees a request the gateway was going to refuse anyway.
    let edits = match wasm::on_request(
        &resolved.filters,
        &resolved.route,
        req.method().as_str(),
        req.path(),
        req.query_string(),
        req.headers(),
    ) {
        FilterOutcome::Continue(edits) => edits,
        FilterOutcome::Stop(stop) => return stopped(*stop),
        // The filter could not run and is not configured to fail open. Its
        // decision is unknown, so the request does not go upstream.
        FilterOutcome::Failed(message) => {
            eprintln!(
                "wasm filter failed for route={} path={}: {message}",
                resolved.route,
                req.path()
            );
            return HttpResponse::InternalServerError().body(format!("{message}\n"));
        }
    };
    // A header a filter set is the gateway's, not the client's: any copy the
    // client sent is dropped, exactly as for auth-injected identity headers.
    blocked.extend(edits.remove);
    blocked.extend(edits.set.iter().map(|(name, _)| name.to_owned()));
    identity.extend(edits.set);

    if websocket::is_upgrade(req.headers()) {
        return websocket::proxy(
            &req,
            payload,
            &client,
            &resolved,
            &target,
            settings.websocket_max_frame_bytes,
            &identity,
            &blocked,
        )
        .await;
    }

    let (scheme, host) = {
        let info = req.connection_info();
        (info.scheme().to_owned(), info.host().to_owned())
    };

    let mut upstream = client
        .request(req.method().clone(), &target)
        .no_decompress();

    let dropped = connection_tokens(req.headers());
    for (name, value) in req.headers().iter() {
        if is_hop_by_hop(name, &dropped)
            || name == "host"
            || name == "content-length"
            || name.as_str().starts_with("x-forwarded-")
            || blocked.contains(name.as_str())
        {
            continue;
        }
        upstream = upstream.append_header((name.clone(), value.clone()));
    }

    if let Some(forwarded_for) = forwarded_for(&req) {
        upstream = upstream.insert_header(("x-forwarded-for", forwarded_for));
    }
    upstream = upstream.insert_header(("x-forwarded-proto", scheme));
    upstream = upstream.insert_header(("x-forwarded-host", host));

    for (header, value) in &identity {
        upstream = upstream.insert_header((header.as_str(), value.as_str()));
    }

    // Preserve the client's framing: re-framing a length-delimited body as
    // chunked drops Content-Length, which some upstreams and WAFs reject.
    let sent = match content_length(req.headers()) {
        Some(len) => upstream.send_body(SizedStream::new(len, payload)).await,
        None => upstream.send_stream(payload).await,
    };

    match sent {
        Ok(response) => relay(response, &resolved.filters, &resolved.route),
        Err(error) => {
            eprintln!(
                "upstream request failed: route={} source={} service={} instance={} target={target} error={error}",
                resolved.route,
                resolved.source,
                resolved.service.as_deref().unwrap_or("-"),
                resolved.instance.as_deref().unwrap_or("-"),
            );
            gateway_error(&error, &resolved)
        }
    }
}

fn relay<S>(response: ClientResponse<S>, filters: &[WasmFilter], route: &str) -> HttpResponse
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, awc::error::PayloadError>> + Unpin + 'static,
{
    let dropped = connection_tokens(response.headers());
    let mut headers: Vec<(HeaderName, HeaderValue)> = response
        .headers()
        .iter()
        .filter(|(name, _)| !is_hop_by_hop(name, &dropped))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    // The body is already streaming by the time a filter sees this, so the
    // response phase can edit headers and nothing else.
    let status = response.status();
    let edits = wasm::on_response(filters, route, status.as_u16(), &headers);
    headers.retain(|(name, _)| !edits.remove.iter().any(|dropped| dropped == name.as_str()));

    let mut builder = HttpResponse::build(status);
    for header in headers {
        builder.append_header(header);
    }
    for (name, value) in edits.set {
        builder.insert_header((name, value));
    }
    builder.streaming(response)
}

/// A filter answered the request itself; the upstream is never contacted.
fn stopped(stop: StopResponse) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(stop.status)
        .unwrap_or(actix_web::http::StatusCode::FORBIDDEN);

    let mut builder = HttpResponse::build(status);
    for (name, value) in stop.headers {
        builder.insert_header((name, value));
    }
    builder.body(stop.body)
}

fn gateway_error(error: &SendRequestError, resolved: &Resolved) -> HttpResponse {
    let timed_out = matches!(
        error,
        SendRequestError::Timeout | SendRequestError::Connect(awc::error::ConnectError::Timeout)
    );

    if timed_out {
        HttpResponse::GatewayTimeout().body(format!(
            "upstream timed out for route '{}'\n",
            resolved.route
        ))
    } else {
        HttpResponse::BadGateway().body(format!(
            "upstream request failed for route '{}'\n",
            resolved.route
        ))
    }
}

pub(crate) fn forwarded_for(req: &HttpRequest) -> Option<String> {
    let existing = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    let peer = req.peer_addr().map(|addr| addr.ip().to_string());

    match (existing, peer) {
        (Some(existing), Some(peer)) => Some(format!("{existing}, {peer}")),
        (Some(existing), None) => Some(existing.to_owned()),
        (None, peer) => peer,
    }
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("content-length")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Header names nominated by a `Connection:` header are hop-by-hop for this
/// message only, so they have to be discovered per request rather than listed.
pub(crate) fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("connection")
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

pub(crate) fn is_hop_by_hop(name: &HeaderName, connection_tokens: &[String]) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
        || connection_tokens.iter().any(|token| token == name.as_str())
}
