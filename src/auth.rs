use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use actix_web::http::header::{HeaderMap, HeaderValue};
use awc::Client;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};
use yaml_serde::Value as Yaml;

use crate::config::{PluginConfig, PluginReference};

pub enum AuthPolicy {
    StaticToken {
        header_keys: Vec<String>,
        tokens: Vec<String>,
    },
    JwtHs256 {
        header_keys: Vec<String>,
        key: DecodingKey,
        validation: Validation,
        roles_claim: String,
    },
    OAuth2(OAuth2Policy),
}

pub struct OAuth2Policy {
    header_keys: Vec<String>,
    introspection_url: String,
    userinfo_url: Option<String>,
    authorization: String,
    roles_claim: String,
    timeout: Duration,
    cache_max: Duration,
    cache_negative: Duration,
    cache_max_entries: usize,
    cache: Mutex<HashMap<[u8; 32], CacheEntry>>,
}

struct CacheEntry {
    outcome: CachedOutcome,
    expires_at: Instant,
}

#[derive(Clone)]
enum CachedOutcome {
    Active(Arc<Map<String, Json>>),
    Inactive,
}

#[derive(Clone)]
pub struct RouteGuard {
    policy: Arc<AuthPolicy>,
    name: String,
    required_roles: Vec<String>,
    insert_headers: Vec<(String, String)>,
}

pub enum AuthOutcome {
    Allowed(Vec<(String, String)>),
    Unauthorized(String),
    Forbidden(String),
    Unavailable(String),
}

/// Every guard on a route must pass; identity headers from all of them are merged.
pub async fn enforce(
    guards: &[RouteGuard],
    headers: &HeaderMap,
    client: &Client,
) -> AuthOutcome {
    let mut identity = Vec::new();

    for guard in guards {
        match guard.check(headers, client).await {
            Ok(mut injected) => identity.append(&mut injected),
            Err(outcome) => return outcome,
        }
    }

    AuthOutcome::Allowed(identity)
}

/// Header names the gateway itself sets from verified claims. Client-supplied
/// copies must be dropped before forwarding or a caller could forge identity.
pub fn injected_header_names(guards: &[RouteGuard]) -> HashSet<String> {
    guards
        .iter()
        .flat_map(|guard| guard.insert_headers.iter())
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect()
}

impl AuthPolicy {
    pub fn from_config(config: &PluginConfig) -> Result<Self, String> {
        let header_keys = string_list(&config.params, "keys")?;

        match config.plugin_id.as_str() {
            "token-plugin" => {
                let tokens = string_list(&config.params, "tokens")?;
                if tokens.is_empty() {
                    return Err("token-plugin requires a non-empty 'tokens' list".to_owned());
                }
                if tokens.iter().any(|token| token.is_empty()) {
                    return Err("token-plugin 'tokens' must not contain empty values".to_owned());
                }
                Ok(AuthPolicy::StaticToken {
                    header_keys,
                    tokens,
                })
            }
            "jwt-plugin" => {
                let secret = string(&config.params, "secret")?
                    .ok_or_else(|| "jwt-plugin requires 'secret'".to_owned())?;
                if secret.is_empty() {
                    return Err("jwt-plugin 'secret' must not be empty".to_owned());
                }

                let mut validation = Validation::new(Algorithm::HS256);
                if let Some(issuer) = string(&config.params, "issuer")? {
                    validation.set_issuer(&[issuer]);
                }
                match string(&config.params, "audience")? {
                    Some(audience) => validation.set_audience(&[audience]),
                    // jsonwebtoken validates `aud` by default; without a configured
                    // audience that would reject every token carrying one.
                    None => validation.validate_aud = false,
                }

                let roles_claim =
                    string(&config.params, "roles-claim")?.unwrap_or_else(|| "roles".to_owned());

                Ok(AuthPolicy::JwtHs256 {
                    header_keys,
                    key: DecodingKey::from_secret(secret.as_bytes()),
                    validation,
                    roles_claim,
                })
            }
            "oauth2-plugin" => {
                let introspection_url = string(&config.params, "introspection-url")?
                    .ok_or_else(|| "oauth2-plugin requires 'introspection-url'".to_owned())?;
                let client_id = string(&config.params, "client-id")?
                    .ok_or_else(|| "oauth2-plugin requires 'client-id'".to_owned())?;
                let client_secret = string(&config.params, "client-secret")?
                    .ok_or_else(|| "oauth2-plugin requires 'client-secret'".to_owned())?;

                Ok(AuthPolicy::OAuth2(OAuth2Policy {
                    header_keys,
                    introspection_url,
                    userinfo_url: string(&config.params, "userinfo-url")?,
                    authorization: format!(
                        "Basic {}",
                        STANDARD.encode(format!("{client_id}:{client_secret}"))
                    ),
                    // OAuth2 authorization is scope-based by default.
                    roles_claim: string(&config.params, "roles-claim")?
                        .unwrap_or_else(|| "scope".to_owned()),
                    timeout: Duration::from_secs(seconds(&config.params, "timeout-seconds", 5)?),
                    cache_max: Duration::from_secs(seconds(
                        &config.params,
                        "cache-max-seconds",
                        60,
                    )?),
                    cache_negative: Duration::from_secs(seconds(
                        &config.params,
                        "cache-negative-seconds",
                        5,
                    )?),
                    cache_max_entries: seconds(&config.params, "cache-max-entries", 10_000)?
                        as usize,
                    cache: Mutex::new(HashMap::new()),
                }))
            }
            other => Err(format!(
                "unknown plugin type '{other}' (expected 'token-plugin', 'jwt-plugin' or 'oauth2-plugin')"
            )),
        }
    }

    fn header_keys(&self) -> &[String] {
        match self {
            AuthPolicy::StaticToken { header_keys, .. } => header_keys,
            AuthPolicy::JwtHs256 { header_keys, .. } => header_keys,
            AuthPolicy::OAuth2(policy) => &policy.header_keys,
        }
    }
}

impl OAuth2Policy {
    /// Returns the claims the provider vouches for, or an outcome to send back.
    async fn claims(
        &self,
        token: &str,
        client: &Client,
    ) -> Result<Arc<Map<String, Json>>, AuthOutcome> {
        let key = Sha256::digest(token.as_bytes()).into();

        if let Some(cached) = self.cached(&key) {
            return match cached {
                CachedOutcome::Active(claims) => Ok(claims),
                CachedOutcome::Inactive => Err(AuthOutcome::Unauthorized(
                    "token rejected by the authorization provider".to_owned(),
                )),
            };
        }

        let introspection = self.introspect(token, client).await?;

        let active = introspection
            .get("active")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        let expired = introspection
            .get("exp")
            .and_then(Json::as_i64)
            .is_some_and(|exp| exp <= unix_now());

        if !active || expired {
            self.store(key, CachedOutcome::Inactive, self.cache_negative);
            return Err(AuthOutcome::Unauthorized(
                "token rejected by the authorization provider".to_owned(),
            ));
        }

        // Introspection is the authority on validity and scope, so it is laid
        // over the UserInfo profile claims rather than under them.
        let mut claims = match &self.userinfo_url {
            Some(url) => self.userinfo(url, token, client).await?,
            None => Map::new(),
        };
        claims.extend(introspection.clone());

        let ttl = match introspection.get("exp").and_then(Json::as_i64) {
            Some(exp) => self
                .cache_max
                .min(Duration::from_secs((exp - unix_now()).max(0) as u64)),
            None => self.cache_max,
        };

        let claims = Arc::new(claims);
        self.store(key, CachedOutcome::Active(claims.clone()), ttl);
        Ok(claims)
    }

    async fn introspect(
        &self,
        token: &str,
        client: &Client,
    ) -> Result<Map<String, Json>, AuthOutcome> {
        let mut response = client
            .post(&self.introspection_url)
            .timeout(self.timeout)
            .insert_header(("authorization", self.authorization.as_str()))
            .send_form(&[("token", token), ("token_type_hint", "access_token")])
            .await
            .map_err(|error| {
                eprintln!("oauth2 introspection request failed: {error}");
                AuthOutcome::Unavailable("authorization provider is unreachable".to_owned())
            })?;

        if !response.status().is_success() {
            eprintln!(
                "oauth2 introspection returned status {}",
                response.status()
            );
            return Err(AuthOutcome::Unavailable(
                "authorization provider returned an error".to_owned(),
            ));
        }

        response.json::<Map<String, Json>>().await.map_err(|error| {
            eprintln!("oauth2 introspection response was not valid JSON: {error}");
            AuthOutcome::Unavailable("authorization provider returned an invalid response".to_owned())
        })
    }

    async fn userinfo(
        &self,
        url: &str,
        token: &str,
        client: &Client,
    ) -> Result<Map<String, Json>, AuthOutcome> {
        let mut response = client
            .get(url)
            .timeout(self.timeout)
            .insert_header(("authorization", format!("Bearer {token}")))
            .send()
            .await
            .map_err(|error| {
                eprintln!("oauth2 userinfo request failed: {error}");
                AuthOutcome::Unavailable("authorization provider is unreachable".to_owned())
            })?;

        if !response.status().is_success() {
            eprintln!("oauth2 userinfo returned status {}", response.status());
            return Err(AuthOutcome::Unavailable(
                "authorization provider returned an error".to_owned(),
            ));
        }

        response.json::<Map<String, Json>>().await.map_err(|error| {
            eprintln!("oauth2 userinfo response was not valid JSON: {error}");
            AuthOutcome::Unavailable("authorization provider returned an invalid response".to_owned())
        })
    }

    fn cached(&self, key: &[u8; 32]) -> Option<CachedOutcome> {
        let cache = self.cache.lock().unwrap();
        let entry = cache.get(key)?;

        (entry.expires_at > Instant::now()).then(|| entry.outcome.clone())
    }

    fn store(&self, key: [u8; 32], outcome: CachedOutcome, ttl: Duration) {
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();

        if cache.len() >= self.cache_max_entries {
            cache.retain(|_, entry| entry.expires_at > now);
        }
        if cache.len() >= self.cache_max_entries {
            // Still full of live entries: drop the one expiring soonest.
            if let Some(soonest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| *key)
            {
                cache.remove(&soonest);
            }
        }

        cache.insert(
            key,
            CacheEntry {
                outcome,
                expires_at: now + ttl,
            },
        );
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

impl RouteGuard {
    pub fn build(
        name: &str,
        policy: Arc<AuthPolicy>,
        required_roles: Vec<String>,
        insert_headers: Vec<(String, String)>,
    ) -> Result<Self, String> {
        if !required_roles.is_empty() && matches!(*policy, AuthPolicy::StaticToken { .. }) {
            return Err(format!(
                "plugin '{name}' is a token-plugin and carries no claims, so it cannot require roles"
            ));
        }
        for (header, _) in &insert_headers {
            if HeaderValue::from_str(header).is_err() || header.trim().is_empty() {
                return Err(format!("plugin '{name}' has an invalid header name '{header}'"));
            }
        }

        Ok(Self {
            policy,
            name: name.to_owned(),
            required_roles,
            insert_headers,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn from_reference(
        reference: &PluginReference,
        policy: Arc<AuthPolicy>,
    ) -> Result<Self, String> {
        let params = reference.params.clone().unwrap_or_default();
        let roles = string_list(&params, "roles")?;

        let insert_headers = match params.get("insert-headers") {
            Some(Yaml::Mapping(mapping)) => mapping
                .iter()
                .map(|(key, value)| match (key.as_str(), value.as_str()) {
                    (Some(key), Some(value)) => Ok((key.to_owned(), value.to_owned())),
                    _ => Err("'insert-headers' entries must be strings".to_owned()),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err("'insert-headers' must be a mapping".to_owned()),
            None => Vec::new(),
        };

        Self::build(&reference.name, policy, roles, insert_headers)
    }

    async fn check(
        &self,
        headers: &HeaderMap,
        client: &Client,
    ) -> Result<Vec<(String, String)>, AuthOutcome> {
        let Some(token) = extract_token(headers, self.policy.header_keys()) else {
            return Err(AuthOutcome::Unauthorized(format!(
                "missing credentials for '{}'",
                self.name
            )));
        };

        match &*self.policy {
            AuthPolicy::StaticToken { tokens, .. } => {
                let matched = tokens
                    .iter()
                    .any(|candidate| constant_time_eq(candidate.as_bytes(), token.as_bytes()));

                if matched {
                    Ok(Vec::new())
                } else {
                    Err(AuthOutcome::Unauthorized(format!(
                        "invalid credentials for '{}'",
                        self.name
                    )))
                }
            }
            AuthPolicy::JwtHs256 {
                key,
                validation,
                roles_claim,
                ..
            } => {
                let claims = decode::<Map<String, Json>>(&token, key, validation)
                    .map(|data| data.claims)
                    .map_err(|error| {
                        AuthOutcome::Unauthorized(format!(
                            "invalid token for '{}': {:?}",
                            self.name,
                            error.kind()
                        ))
                    })?;

                self.authorize(&claims, roles_claim)?;
                self.render_identity(&claims)
            }
            AuthPolicy::OAuth2(policy) => {
                let claims = policy.claims(&token, client).await?;

                self.authorize(&claims, &policy.roles_claim)?;
                self.render_identity(&claims)
            }
        }
    }

    fn authorize(&self, claims: &Map<String, Json>, roles_claim: &str) -> Result<(), AuthOutcome> {
        let granted = roles(claims, roles_claim);

        match self
            .required_roles
            .iter()
            .find(|required| !granted.contains(*required))
        {
            Some(missing) => Err(AuthOutcome::Forbidden(format!(
                "token lacks required role '{missing}'"
            ))),
            None => Ok(()),
        }
    }

    fn render_identity(
        &self,
        claims: &Map<String, Json>,
    ) -> Result<Vec<(String, String)>, AuthOutcome> {
        let mut rendered = Vec::with_capacity(self.insert_headers.len());

        for (header, template) in &self.insert_headers {
            let Some(value) = render(template, claims) else {
                continue;
            };
            // A claim containing CR/LF would otherwise splice headers downstream.
            if HeaderValue::from_str(&value).is_err() {
                return Err(AuthOutcome::Forbidden(format!(
                    "claim value for header '{header}' is not a valid header value"
                )));
            }
            rendered.push((header.to_owned(), value));
        }

        Ok(rendered)
    }
}

fn extract_token(headers: &HeaderMap, header_keys: &[String]) -> Option<String> {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|token| !token.is_empty());

    if let Some(token) = bearer {
        return Some(token.to_owned());
    }

    header_keys.iter().find_map(|key| {
        headers
            .get(key.as_str())
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
    })
}

fn roles(claims: &Map<String, Json>, roles_claim: &str) -> Vec<String> {
    match claims.get(roles_claim) {
        Some(Json::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
        // OAuth2 `scope` is a space-delimited string rather than an array.
        Some(Json::String(value)) => value.split_whitespace().map(str::to_owned).collect(),
        _ => Vec::new(),
    }
}

fn render(template: &str, claims: &Map<String, Json>) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find('{') {
        let end = rest[start..].find('}')? + start;
        out.push_str(&rest[..start]);

        let claim = &rest[start + 1..end];
        out.push_str(&claim_to_string(claims.get(claim)?)?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);

    Some(out)
}

fn claim_to_string(value: &Json) -> Option<String> {
    match value {
        Json::String(value) => Some(value.to_owned()),
        Json::Number(value) => Some(value.to_string()),
        Json::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Compares without an early exit so a caller cannot learn the correct prefix
/// by timing repeated requests.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b) {
        difference |= left ^ right;
    }
    difference == 0
}

fn string(params: &HashMap<String, Yaml>, key: &str) -> Result<Option<String>, String> {
    match params.get(key) {
        Some(Yaml::String(raw)) => expand_env(raw).map(Some),
        Some(_) => Err(format!("'{key}' must be a string")),
        None => Ok(None),
    }
}

fn seconds(params: &HashMap<String, Yaml>, key: &str, default: u64) -> Result<u64, String> {
    match params.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("'{key}' must be a positive integer")),
        None => Ok(default),
    }
}

fn string_list(params: &HashMap<String, Yaml>, key: &str) -> Result<Vec<String>, String> {
    match params.get(key) {
        Some(Yaml::Sequence(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| format!("'{key}' entries must be strings"))
                    .and_then(expand_env)
            })
            .collect(),
        Some(Yaml::String(raw)) => Ok(vec![expand_env(raw)?]),
        Some(_) => Err(format!("'{key}' must be a list of strings")),
        None => Ok(Vec::new()),
    }
}

/// Expands `$VAR` and `${VAR}`. An unset variable is an error rather than an
/// empty string, so a missing secret cannot silently become a valid credential.
fn expand_env(raw: &str) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();

    while let Some(character) = chars.next() {
        if character != '$' {
            out.push(character);
            continue;
        }

        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }

        let mut name = String::new();
        while let Some(&next) = chars.peek() {
            if next.is_ascii_alphanumeric() || next == '_' {
                name.push(next);
                chars.next();
            } else {
                break;
            }
        }

        if braced && chars.next() != Some('}') {
            return Err(format!("unterminated '${{' in '{raw}'"));
        }
        if name.is_empty() {
            out.push('$');
            continue;
        }

        let value = std::env::var(&name)
            .map_err(|_| format!("environment variable '{name}' referenced by config is not set"))?;
        out.push_str(&value);
    }

    Ok(out)
}
