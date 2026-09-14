//! `testing-plugin`: claim sets posted over HTTP stand in for a real provider.
//!
//! Declared in place of the plugin it impersonates -- same `name:`, so the
//! routes referencing it do not change -- it turns a token into whatever claims
//! were registered for it, with no identity provider reachable and no network
//! call on the request path. That is how roles and `insert-headers` get
//! exercised against a route configured exactly as production configures it.
//!
//! It is also a complete bypass of authentication: anyone who can reach the
//! endpoints below can mint any identity, including any role. Nothing here is
//! safe outside a test environment. The protection is that declaring it is an
//! explicit act, visible in the config, reported by `/registry/describe`, and
//! warned about at startup -- there is no flag that can leave it quietly on.
//!
//!   POST   {endpoint}        {"token": "...", "claims": {...}}  replace
//!   PATCH  {endpoint}        {"token": "...", "claims": {...}}  merge
//!                            (a null claim value removes the claim)
//!   GET    {endpoint}        list overrides (ids, never the tokens)
//!   GET    {endpoint}/{id}   one override
//!   DELETE {endpoint}/{id}   drop one
//!   DELETE {endpoint}        drop all
//!
//! `id` is the token's SHA-256, so it can be pasted around safely. An `exp`
//! claim in the past is still honoured, which is how expiry gets tested.
//!
//! Standing in for an `oauth2-plugin` means standing in for its session cookie
//! too, so this takes the same `session-cookie:` block and mints the same
//! thing. A request already carrying one is read as the *baseline* it starts
//! from: the claims in the cookie, with whatever was registered for the token
//! layered over them. That is what lets a test log in once and then change one
//! claim -- add a role, expire the session, drop an email -- without restating
//! the identity each time, and it is why a route with a cookie in place works
//! here with nothing registered at all.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use actix_web::{web, HttpResponse};
use awc::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};

use crate::auth::AuthOutcome;
use crate::config::PluginConfig;
use crate::plugins::session::SessionCookie;
use crate::plugins::{self, AuthPlugin, Authenticating, Credential, Endpoint};

pub const KIND: &str = "testing-plugin";

const DEFAULT_ENDPOINT: &str = "/testing/userinfo";

pub struct TestingPlugin {
    name: String,
    header_keys: Vec<String>,
    cookie_keys: Vec<String>,
    roles_claim: String,
    endpoint: String,
    session: Option<SessionCookie>,
    overrides: Arc<ClaimOverrides>,
}

pub fn build(config: &PluginConfig) -> Result<TestingPlugin, String> {
    let endpoint = plugins::string(&config.params, "endpoint")?
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());

    if !endpoint.starts_with('/') {
        return Err(format!("{KIND} 'endpoint' must start with '/'"));
    }

    let session = plugins::session::build(&config.params, KIND)?;

    Ok(TestingPlugin {
        name: config.name.to_owned(),
        header_keys: plugins::string_list(&config.params, "keys")?,
        // Unlike the oauth2-plugin it stands in for, this *does* accept its own
        // cookie back: there is no provider to ask, so a live session is the
        // only identity a browser has once the login response is behind it.
        cookie_keys: session
            .as_ref()
            .map(|cookie| vec![cookie.name().to_owned()])
            .unwrap_or_default(),
        // Defaults to the oauth2-plugin's claim, which is what this most often
        // stands in for.
        roles_claim: plugins::string(&config.params, "roles-claim")?
            .unwrap_or_else(|| "scope".to_owned()),
        endpoint,
        session,
        overrides: Arc::new(ClaimOverrides::default()),
    })
}

impl AuthPlugin for TestingPlugin {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn header_keys(&self) -> &[String] {
        &self.header_keys
    }

    fn cookie_keys(&self) -> &[String] {
        &self.cookie_keys
    }

    fn session_cookie(&self) -> Option<&SessionCookie> {
        self.session.as_ref()
    }

    fn roles_claim(&self) -> Option<&str> {
        Some(&self.roles_claim)
    }

    fn authenticate<'a>(
        &'a self,
        credential: Credential<'a>,
        _client: &'a Client,
    ) -> Authenticating<'a> {
        let outcome = self.resolve(credential);

        Box::pin(async move { outcome })
    }

    /// The claim sets have to be posted from somewhere, so this plugin -- alone
    /// among them -- asks the proxy listener to mount a scope for it.
    fn endpoint(&self) -> Option<Endpoint> {
        let overrides = self.overrides.clone();
        let path = self.endpoint.to_owned();

        Some(Endpoint {
            plugin: self.name.to_owned(),
            path: self.endpoint.to_owned(),
            configure: Arc::new(move |cfg: &mut web::ServiceConfig| {
                cfg.service(
                    web::scope(&path)
                        // `Data::from` reuses the plugin's own store rather
                        // than wrapping a second Arc around it.
                        .app_data(web::Data::from(overrides.clone()))
                        .route("", web::post().to(replace))
                        .route("", web::patch().to(patch))
                        .route("", web::get().to(list))
                        .route("", web::delete().to(clear))
                        .route("/{id}", web::get().to(show))
                        .route("/{id}", web::delete().to(remove)),
                );
            }),
        })
    }
}

impl TestingPlugin {
    /// The identity a request presents: the session it already holds, with
    /// anything registered for its token layered over the top.
    ///
    /// The layering is the useful part. A test that has logged in and wants to
    /// try one more role registers that one claim against the token, and the
    /// rest of the identity keeps coming from the cookie -- so what is being
    /// varied is visible in the test rather than buried in a full claim set
    /// restated for the occasion.
    fn resolve(&self, credential: Credential<'_>) -> Result<Arc<Map<String, Json>>, AuthOutcome> {
        let baseline = credential
            .session
            .zip(self.session.as_ref())
            .and_then(|(cookie, session)| session.claims(cookie));
        let registered = self.overrides.get(credential.token);

        let claims = match (baseline, registered) {
            // Nothing vouches for this caller, which is what an unknown token
            // means when there is no provider to fall back to.
            (None, None) => return Err(rejected()),
            (None, Some(registered)) => registered,
            (Some(baseline), None) => Arc::new(baseline),
            (Some(mut baseline), Some(registered)) => {
                baseline.extend((*registered).clone());
                Arc::new(baseline)
            }
        };

        // Honoured rather than ignored: a past `exp` is how expiry is tested,
        // and it has to behave the way a real provider's would. Registering
        // `exp` against a token is therefore how a live session is expired
        // mid-test without waiting for the cookie to run out.
        if expired(&claims) {
            return Err(rejected());
        }
        Ok(claims)
    }
}

/// Deliberately indistinguishable from a real provider's refusal, so a test
/// exercises the same path a production rejection would.
fn rejected() -> AuthOutcome {
    AuthOutcome::Unauthorized("token rejected by the authorization provider".to_owned())
}

fn expired(claims: &Map<String, Json>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);

    claims
        .get("exp")
        .and_then(Json::as_i64)
        .is_some_and(|exp| exp <= now)
}

/// Claim sets that stand in for a live authorization provider.
///
/// One store per declared plugin, shared across worker threads so an override
/// posted on one connection is visible to the next request on any other.
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::FutureExt;
    use serde_json::json;

    fn plugin(params: &str) -> Result<TestingPlugin, String> {
        build(&PluginConfig {
            name: "stands-in-for-oauth".to_owned(),
            plugin_id: KIND.to_owned(),
            params: yaml_serde::from_str(params).expect("invalid test params"),
        })
    }

    fn claims(value: Json) -> Map<String, Json> {
        value.as_object().unwrap().to_owned()
    }

    fn verify(plugin: &TestingPlugin, token: &str) -> Result<Arc<Map<String, Json>>, AuthOutcome> {
        with_session(plugin, token, None)
    }

    fn with_session(
        plugin: &TestingPlugin,
        token: &str,
        session: Option<&str>,
    ) -> Result<Arc<Map<String, Json>>, AuthOutcome> {
        plugin
            .authenticate(Credential { token, session }, &Client::default())
            .now_or_never()
            .expect("a lookup is synchronous and must resolve immediately")
    }

    /// Logs an identity in the way the plugin itself would, and hands back the
    /// cookie value a browser would then carry.
    fn login(plugin: &TestingPlugin, claims: Json) -> String {
        let issued = plugin.issue(
            Credential {
                token: "opaque",
                session: None,
            },
            claims.as_object().unwrap(),
        );
        assert_eq!(issued.len(), 1, "a configured cookie must be minted");

        issued[0]
            .1
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_owned()
    }

    fn far_future() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600
    }

    #[test]
    fn the_endpoint_defaults_to_the_documented_path() {
        assert_eq!(
            plugin("{}").unwrap().endpoint().unwrap().path,
            DEFAULT_ENDPOINT
        );
        assert_eq!(plugin("endpoint: /elsewhere").unwrap().endpoint, "/elsewhere");
        // A path that is not a path would mount a scope nothing can reach.
        assert!(plugin("endpoint: elsewhere").is_err());
    }

    #[test]
    fn it_stands_in_for_the_oauth_plugin_by_default() {
        assert_eq!(plugin("{}").unwrap().roles_claim(), Some("scope"));
        assert_eq!(plugin("roles-claim: roles").unwrap().roles_claim(), Some("roles"));
    }

    #[test]
    fn a_registered_claim_set_becomes_the_verified_identity() {
        let plugin = plugin("{}").unwrap();
        plugin
            .overrides
            .put("t", claims(json!({"sub": "u1", "scope": "admin"})));

        let verified = verify(&plugin, "t").expect("a registered token must verify");
        assert_eq!(verified["sub"], json!("u1"));
    }

    #[test]
    fn a_token_nobody_registered_is_refused() {
        let plugin = plugin("{}").unwrap();

        // No provider to fall back to: an unknown token is simply not valid.
        assert!(matches!(
            verify(&plugin, "unknown"),
            Err(AuthOutcome::Unauthorized(_))
        ));
    }

    #[test]
    fn a_past_expiry_is_honoured_so_expiry_can_be_tested() {
        let plugin = plugin("{}").unwrap();

        plugin.overrides.put("live", claims(json!({"exp": far_future()})));
        plugin.overrides.put("dead", claims(json!({"exp": 1})));

        assert!(verify(&plugin, "live").is_ok());
        assert!(verify(&plugin, "dead").is_err());
    }

    #[test]
    fn a_session_already_in_place_is_the_identity_on_its_own() {
        let plugin = plugin("session-cookie: {secret: shh}").unwrap();
        let cookie = login(&plugin, json!({"sub": "u1", "scope": "admin"}));

        // Nothing registered for this token: the cookie is all there is, and
        // it is enough. A route behind a login works with no setup at all.
        let verified = with_session(&plugin, &cookie, Some(&cookie))
            .expect("a live session must authenticate");

        assert_eq!(verified["sub"], json!("u1"));
        assert_eq!(verified["scope"], json!("admin"));
    }

    #[test]
    fn a_registered_claim_is_layered_over_the_session_it_arrives_with() {
        let plugin = plugin("session-cookie: {secret: shh}").unwrap();
        let cookie = login(&plugin, json!({"sub": "u1", "email": "a@b.c", "scope": "user"}));

        // The test varies one claim; the rest of the identity keeps coming
        // from the session, whatever credential the token came from.
        plugin.overrides.put("t", claims(json!({"scope": "admin"})));
        let verified =
            with_session(&plugin, "t", Some(&cookie)).expect("the session is the baseline");

        assert_eq!(verified["scope"], json!("admin"));
        assert_eq!(verified["sub"], json!("u1"));
        assert_eq!(verified["email"], json!("a@b.c"));
    }

    #[test]
    fn a_registered_expiry_ends_a_live_session() {
        let plugin = plugin("session-cookie: {secret: shh}").unwrap();
        let cookie = login(&plugin, json!({"sub": "u1"}));

        assert!(with_session(&plugin, &cookie, Some(&cookie)).is_ok());

        // Expiring the session is a one-claim override, not a wait.
        plugin.overrides.put(&cookie, claims(json!({"exp": 1})));
        assert!(matches!(
            with_session(&plugin, &cookie, Some(&cookie)),
            Err(AuthOutcome::Unauthorized(_))
        ));
    }

    #[test]
    fn a_cookie_this_plugin_did_not_mint_is_not_an_identity() {
        let forger = plugin("session-cookie: {secret: guessed}").unwrap();
        let cookie = login(&forger, json!({"sub": "admin", "scope": "admin"}));
        let plugin = plugin("session-cookie: {secret: shh}").unwrap();

        // Test scaffolding still checks a signature: the endpoints are the
        // documented way to mint an identity, a handmade cookie is not.
        assert!(matches!(
            with_session(&plugin, &cookie, Some(&cookie)),
            Err(AuthOutcome::Unauthorized(_))
        ));
    }

    #[test]
    fn without_a_configured_cookie_there_is_no_session_to_read() {
        let plugin = plugin("{}").unwrap();

        assert!(plugin.session_cookie().is_none());
        assert!(plugin.cookie_keys().is_empty());
        assert!(with_session(&plugin, "t", Some("anything")).is_err());
    }

    #[test]
    fn patching_replaces_present_claims_and_a_null_removes_one() {
        let overrides = ClaimOverrides::default();
        overrides.put("t", claims(json!({"sub": "u1", "email": "a@b.c"})));

        let merged = overrides.merge("t", claims(json!({"email": "new@b.c", "scope": "admin"})));
        assert_eq!(merged["sub"], json!("u1"));
        assert_eq!(merged["email"], json!("new@b.c"));
        assert_eq!(merged["scope"], json!("admin"));

        let pruned = overrides.merge("t", claims(json!({"email": null})));
        assert!(!pruned.contains_key("email"));
        assert_eq!(pruned["sub"], json!("u1"));
    }

    #[test]
    fn an_override_is_addressed_by_digest_never_by_the_token() {
        let overrides = ClaimOverrides::default();
        overrides.put("t", claims(json!({"sub": "u1"})));

        let listed = overrides.list();
        assert_eq!(listed.len(), 1);

        let id = &listed[0].id;
        // The id is the token's SHA-256, so it can be pasted around safely.
        assert_eq!(id, &hex(&key_for("t")));
        assert_ne!(id, "t");

        assert!(overrides.show(id).is_some());
        assert!(overrides.remove(id));
        assert!(overrides.show(id).is_none());

        // An id that is not a digest addresses nothing.
        assert!(!overrides.remove("t"));
        assert!(overrides.show("nonsense").is_none());
    }

    #[test]
    fn clearing_reports_how_many_it_dropped() {
        let overrides = ClaimOverrides::default();
        overrides.put("a", claims(json!({})));
        overrides.put("b", claims(json!({})));

        assert_eq!(overrides.clear(), 2);
        assert_eq!(overrides.clear(), 0);
    }
}
