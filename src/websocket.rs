use std::collections::HashSet;

use actix_web::http::header::HeaderMap;
use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::{CloseReason, Message, MessageStream, ProtocolError, Session};
use awc::ws::{self, Frame};
use awc::Client;
use bytestring::ByteString;
use futures_util::{SinkExt, Stream, StreamExt};

use crate::proxy::{connection_tokens, forwarded_for, is_hop_by_hop};
use crate::registry::Resolved;

pub fn is_upgrade(headers: &HeaderMap) -> bool {
    let upgrades_to_websocket = headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));

    upgrades_to_websocket
        && connection_tokens(headers)
            .iter()
            .any(|token| token == "upgrade")
}

pub async fn proxy(
    req: &HttpRequest,
    payload: web::Payload,
    client: &Client,
    resolved: &Resolved,
    target: &str,
    max_frame_bytes: usize,
    identity: &[(String, String)],
    reserved: &HashSet<String>,
) -> HttpResponse {
    let mut upstream_request = client
        .ws(websocket_url(target))
        .max_frame_size(max_frame_bytes);

    let requested = requested_protocols(req.headers());
    if !requested.is_empty() {
        upstream_request = upstream_request.protocols(requested.iter());
    }

    let dropped = connection_tokens(req.headers());
    for (name, value) in req.headers().iter() {
        // awc writes its own handshake headers; relaying the client's key or
        // version would produce a handshake the upstream rejects.
        if is_hop_by_hop(name, &dropped)
            || name == "host"
            || name == "content-length"
            || name.as_str().starts_with("sec-websocket-")
            || name.as_str().starts_with("x-forwarded-")
            || reserved.contains(name.as_str())
        {
            continue;
        }
        upstream_request = upstream_request.header(name.clone(), value.clone());
    }

    for (header, value) in identity {
        upstream_request = upstream_request.set_header(header.as_str(), value.as_str());
    }

    if let Some(value) = forwarded_for(req) {
        upstream_request = upstream_request.set_header("x-forwarded-for", value);
    }
    let (scheme, host) = {
        let info = req.connection_info();
        (info.scheme().to_owned(), info.host().to_owned())
    };
    upstream_request = upstream_request.set_header("x-forwarded-proto", scheme);
    upstream_request = upstream_request.set_header("x-forwarded-host", host);

    let (upstream_response, upstream) = match upstream_request.connect().await {
        Ok(connected) => connected,
        Err(error) => {
            eprintln!(
                "websocket upgrade failed: route={} service={} instance={} target={target} error={error}",
                resolved.route,
                resolved.service.as_deref().unwrap_or("-"),
                resolved.instance.as_deref().unwrap_or("-"),
            );
            return HttpResponse::BadGateway().body(format!(
                "upstream websocket upgrade failed for route '{}'\n",
                resolved.route
            ));
        }
    };

    let negotiated = upstream_response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let negotiated: Vec<&str> = negotiated.iter().map(String::as_str).collect();

    match actix_ws::handle_with_protocols(req, payload, &negotiated) {
        Ok((response, session, stream)) => {
            actix_web::rt::spawn(relay(
                session,
                stream.max_frame_size(max_frame_bytes),
                upstream,
            ));
            response
        }
        Err(error) => error.error_response(),
    }
}

/// Pumps frames in both directions until either peer closes, then closes the
/// other side with the same reason.
async fn relay<S, E>(mut session: Session, mut client: MessageStream, mut upstream: S)
where
    S: Stream<Item = Result<Frame, ProtocolError>> + SinkExt<ws::Message, Error = E> + Unpin,
{
    let reason = loop {
        tokio::select! {
            from_client = client.next() => match from_client {
                Some(Ok(Message::Text(text))) => {
                    if upstream.send(ws::Message::Text(text)).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Message::Binary(data))) => {
                    if upstream.send(ws::Message::Binary(data)).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Message::Continuation(item))) => {
                    if upstream.send(ws::Message::Continuation(item)).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    if upstream.send(ws::Message::Ping(data)).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Message::Pong(data))) => {
                    if upstream.send(ws::Message::Pong(data)).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Message::Close(reason))) => {
                    let _ = upstream.send(ws::Message::Close(reason.clone())).await;
                    break reason;
                }
                Some(Ok(Message::Nop)) => {}
                Some(Err(error)) => break Some(protocol_close("client", &error)),
                None => break None,
            },
            from_upstream = upstream.next() => match from_upstream {
                Some(Ok(Frame::Text(data))) => {
                    let Ok(text) = ByteString::try_from(data) else {
                        break Some(CloseReason::from(actix_ws::CloseCode::Invalid));
                    };
                    if session.text(text).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Frame::Binary(data))) => {
                    if session.binary(data).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Frame::Continuation(item))) => {
                    if session.continuation(item).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Frame::Ping(data))) => {
                    if session.ping(&data).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Frame::Pong(data))) => {
                    if session.pong(&data).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(Frame::Close(reason))) => break reason,
                Some(Err(error)) => break Some(protocol_close("upstream", &error)),
                None => break None,
            },
        }
    };

    let _ = session.close(reason).await;
}

/// Without this a frame that trips the size limit closes with 1005 "no status",
/// which gives the client nothing to diagnose.
fn protocol_close(peer: &str, error: &ProtocolError) -> CloseReason {
    eprintln!("websocket {peer} protocol error: {error}");

    match error {
        ProtocolError::Overflow | ProtocolError::InvalidLength(_) => CloseReason {
            code: actix_ws::CloseCode::Size,
            description: Some(format!("{peer} frame exceeds gateway limit")),
        },
        _ => CloseReason::from(actix_ws::CloseCode::Protocol),
    }
}

fn websocket_url(target: &str) -> String {
    match target.split_once("://") {
        Some(("http", rest)) => format!("ws://{rest}"),
        Some(("https", rest)) => format!("wss://{rest}"),
        _ => target.to_owned(),
    }
}

fn requested_protocols(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("sec-websocket-protocol")
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|protocol| protocol.trim().to_owned())
        .filter(|protocol| !protocol.is_empty())
        .collect()
}
