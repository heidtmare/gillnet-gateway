use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};

/// Claim sets that stand in for a live authorization provider.
///
/// A token with an override here skips introspection and UserInfo entirely:
/// the stored claims *are* the verified identity. That is the whole point --
/// it lets roles and `insert-headers` be exercised with no IdP reachable --
/// and it is also why the routes below are mounted only when
/// `testing.userinfo-overrides` is true. Anyone who can reach them can mint
/// any identity they like, so this must stay off in production.
#[derive(Default)]
pub struct ClaimOverrides {
    entries: RwLock<HashMap<[u8; 32], Arc<Map<String, Json>>>>,
}

impl ClaimOverrides {
    /// The claims registered for this token, if any. Cheap enough to call on
    /// every request: one hash and an uncontended read lock.
    pub fn get(&self, token: &str) -> Option<Arc<Map<String, Json>>> {
        self.entries.read().unwrap().get(&key_for(token)).cloned()
    }

    fn put(&self, token: &str, claims: Map<String, Json>) -> Arc<Map<String, Json>> {
        let claims = Arc::new(claims);
        self.entries
            .write()
            .unwrap()
            .insert(key_for(token), claims.clone());
        claims
    }

    /// Applies RFC 7386 merge semantics over whatever is already stored for
    /// the token: present keys are replaced, a `null` value removes the claim,
    /// everything else is left alone.
    fn merge(&self, token: &str, patch: Map<String, Json>) -> Arc<Map<String, Json>> {
        let mut entries = self.entries.write().unwrap();
        let key = key_for(token);

        let mut claims = entries
            .get(&key)
            .map(|existing| (**existing).clone())
            .unwrap_or_default();

        for (claim, value) in patch {
            match value {
                Json::Null => {
                    claims.remove(&claim);
                }
                value => {
                    claims.insert(claim, value);
                }
            }
        }

        let claims = Arc::new(claims);
        entries.insert(key, claims.clone());
        claims
    }

    fn remove(&self, id: &str) -> bool {
        let Some(key) = key_from_id(id) else {
            return false;
        };
        self.entries.write().unwrap().remove(&key).is_some()
    }

    fn clear(&self) -> usize {
        let mut entries = self.entries.write().unwrap();
        let removed = entries.len();
        entries.clear();
        removed
    }

    fn list(&self) -> Vec<OverrideView> {
        let mut views: Vec<OverrideView> = self
            .entries
            .read()
            .unwrap()
            .iter()
            .map(|(key, claims)| OverrideView {
                id: hex(key),
                claims: (**claims).clone(),
            })
            .collect();

        views.sort_by(|a, b| a.id.cmp(&b.id));
        views
    }

    fn show(&self, id: &str) -> Option<OverrideView> {
        let key = key_from_id(id)?;
        let entries = self.entries.read().unwrap();
        let claims = entries.get(&key)?;

        Some(OverrideView {
            id: hex(&key),
            claims: (**claims).clone(),
        })
    }
}

/// Overrides are keyed by digest so a bearer token never sits in the map, and
/// so the `id` handed back by these endpoints can be shared without handing
/// over the credential it stands for.
fn key_for(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn key_from_id(id: &str) -> Option<[u8; 32]> {
    if id.len() != 64 {
        return None;
    }

    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(id.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}

fn hex(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideRequest {
    token: String,

    #[serde(default)]
    claims: Map<String, Json>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OverrideView {
    id: String,
    claims: Map<String, Json>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OverrideListView {
    overrides: Vec<OverrideView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemovedResponse {
    removed: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

type SharedOverrides = web::Data<ClaimOverrides>;

/// Mounted on the proxy listener, and only when the config says so. The scope
/// shadows any configured route under the same prefix, which is one more
/// reason to leave it off outside a test environment.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/testing")
            .route("/userinfo", web::post().to(replace))
            .route("/userinfo", web::patch().to(patch))
            .route("/userinfo", web::get().to(list))
            .route("/userinfo", web::delete().to(clear))
            .route("/userinfo/{id}", web::get().to(show))
            .route("/userinfo/{id}", web::delete().to(remove)),
    );
}

/// Replaces the whole claim set for a token.
async fn replace(body: web::Json<OverrideRequest>, overrides: SharedOverrides) -> HttpResponse {
    let request = body.into_inner();
    if let Some(error) = reject(&request) {
        return error;
    }

    let id = hex(&key_for(&request.token));
    let claims = overrides.put(&request.token, request.claims);

    println!("testing: set userinfo claim override {id}");
    HttpResponse::Ok().json(OverrideView {
        id,
        claims: (*claims).clone(),
    })
}

/// Merges into the claim set for a token, creating it if absent.
async fn patch(body: web::Json<OverrideRequest>, overrides: SharedOverrides) -> HttpResponse {
    let request = body.into_inner();
    if let Some(error) = reject(&request) {
        return error;
    }

    let id = hex(&key_for(&request.token));
    let claims = overrides.merge(&request.token, request.claims);

    println!("testing: patched userinfo claim override {id}");
    HttpResponse::Ok().json(OverrideView {
        id,
        claims: (*claims).clone(),
    })
}

async fn list(overrides: SharedOverrides) -> HttpResponse {
    HttpResponse::Ok().json(OverrideListView {
        overrides: overrides.list(),
    })
}

async fn show(path: web::Path<String>, overrides: SharedOverrides) -> HttpResponse {
    let id = path.into_inner();

    match overrides.show(&id) {
        Some(view) => HttpResponse::Ok().json(view),
        None => HttpResponse::NotFound().json(ErrorResponse {
            error: format!("no claim override with id '{id}'"),
        }),
    }
}

async fn remove(path: web::Path<String>, overrides: SharedOverrides) -> HttpResponse {
    let id = path.into_inner();

    if overrides.remove(&id) {
        println!("testing: removed userinfo claim override {id}");
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().json(ErrorResponse {
            error: format!("no claim override with id '{id}'"),
        })
    }
}

async fn clear(overrides: SharedOverrides) -> HttpResponse {
    let removed = overrides.clear();

    println!("testing: cleared {removed} userinfo claim override(s)");
    HttpResponse::Ok().json(RemovedResponse { removed })
}

fn reject(request: &OverrideRequest) -> Option<HttpResponse> {
    request.token.trim().is_empty().then(|| {
        HttpResponse::BadRequest().json(ErrorResponse {
            error: "token must not be empty".to_owned(),
        })
    })
}
