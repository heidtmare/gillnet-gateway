//! `oauth2-plugin`: the authorization provider is asked about every token.
//!
//! RFC 7662 introspection decides whether a token is live, and UserInfo fills
//! in the profile claims. Because that is a network call on the request path,
//! answers are cached until the token's own `exp`, capped by
//! `cache-max-seconds`. When the provider cannot be reached the request is
//! refused with 503 rather than guessed at: the token may well be valid, but
//! nothing here can confirm it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use awc::Client;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};

use crate::auth::AuthOutcome;
use crate::config::PluginConfig;
use crate::plugins::{self, AuthPlugin, Authenticating};

pub const KIND: &str = "oauth2-plugin";

pub struct OAuth2Plugin {
    name: String,
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

pub fn build(config: &PluginConfig) -> Result<OAuth2Plugin, String> {
    let params = &config.params;

    let introspection_url = plugins::string(params, "introspection-url")?
        .ok_or_else(|| format!("{KIND} requires 'introspection-url'"))?;
    let client_id =
        plugins::string(params, "client-id")?.ok_or_else(|| format!("{KIND} requires 'client-id'"))?;
    let client_secret = plugins::string(params, "client-secret")?
        .ok_or_else(|| format!("{KIND} requires 'client-secret'"))?;

    Ok(OAuth2Plugin {
        name: config.name.to_owned(),
        header_keys: plugins::string_list(params, "keys")?,
        introspection_url,
        userinfo_url: plugins::string(params, "userinfo-url")?,
        authorization: format!(
            "Basic {}",
            STANDARD.encode(format!("{client_id}:{client_secret}"))
        ),
        // OAuth2 authorization is scope-based by default.
        roles_claim: plugins::string(params, "roles-claim")?.unwrap_or_else(|| "scope".to_owned()),
        timeout: Duration::from_secs(plugins::number(params, "timeout-seconds", 5)?),
        cache_max: Duration::from_secs(plugins::number(params, "cache-max-seconds", 60)?),
        cache_negative: Duration::from_secs(plugins::number(params, "cache-negative-seconds", 5)?),
        cache_max_entries: plugins::number(params, "cache-max-entries", 10_000)? as usize,
        cache: Mutex::new(HashMap::new()),
    })
}

impl AuthPlugin for OAuth2Plugin {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn header_keys(&self) -> &[String] {
        &self.header_keys
    }

    fn roles_claim(&self) -> Option<&str> {
        Some(&self.roles_claim)
    }

    fn authenticate<'a>(&'a self, token: &'a str, client: &'a Client) -> Authenticating<'a> {
        Box::pin(self.claims(token, client))
    }
}

impl OAuth2Plugin {
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
                CachedOutcome::Inactive => Err(rejected()),
            };
        }

        let introspection = self.introspect(token, client).await?;

        let active = introspection
            .get("active")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        if !active || expired(&introspection) {
            self.store(key, CachedOutcome::Inactive, self.cache_negative);
            return Err(rejected());
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

/// Deliberately the same message whether the token was never valid, has
/// expired, or was revoked: which of those is true is not the caller's to know.
fn rejected() -> AuthOutcome {
    AuthOutcome::Unauthorized("token rejected by the authorization provider".to_owned())
}

/// An `exp` in the past, whether it came from the provider or from a test
/// override, means the token is no longer good.
fn expired(claims: &Map<String, Json>) -> bool {
    claims
        .get("exp")
        .and_then(Json::as_i64)
        .is_some_and(|exp| exp <= unix_now())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plugin(params: &str) -> Result<OAuth2Plugin, String> {
        build(&PluginConfig {
            name: "test-oauth".to_owned(),
            plugin_id: KIND.to_owned(),
            params: yaml_serde::from_str(params).expect("invalid test params"),
        })
    }

    fn complete() -> &'static str {
        "{introspection-url: 'https://idp/introspect', client-id: gw, client-secret: shh}"
    }

    fn claims(json: Json) -> Map<String, Json> {
        json.as_object().unwrap().to_owned()
    }

    #[test]
    fn every_credential_the_provider_needs_is_required() {
        assert!(plugin("{client-id: gw, client-secret: shh}").is_err());
        assert!(plugin("{introspection-url: 'https://idp/i', client-secret: shh}").is_err());
        assert!(plugin("{introspection-url: 'https://idp/i', client-id: gw}").is_err());
        assert!(plugin(complete()).is_ok());
    }

    #[test]
    fn credentials_become_a_basic_header_and_are_not_otherwise_kept() {
        let plugin = plugin(complete()).unwrap();

        // "gw:shh" base64-encoded.
        assert_eq!(plugin.authorization, "Basic Z3c6c2ho");
    }

    #[test]
    fn authorization_is_scope_based_unless_told_otherwise() {
        assert_eq!(plugin(complete()).unwrap().roles_claim(), Some("scope"));

        let params = format!("{{{}, roles-claim: roles}}", complete().trim_matches(['{', '}']));
        assert_eq!(plugin(&params).unwrap().roles_claim(), Some("roles"));
    }

    #[test]
    fn a_past_expiry_is_treated_as_expired() {
        assert!(expired(&claims(json!({"exp": 1}))));
        assert!(!expired(&claims(json!({"exp": unix_now() + 3600}))));
        // No `exp` at all means the provider did not bound the token; that is
        // its call to make, not a reason to reject.
        assert!(!expired(&claims(json!({"sub": "u1"}))));
    }

    #[test]
    fn a_cached_answer_is_returned_until_it_expires() {
        let plugin = plugin(complete()).unwrap();
        let key = [7u8; 32];

        plugin.store(key, CachedOutcome::Inactive, Duration::from_secs(60));
        assert!(matches!(plugin.cached(&key), Some(CachedOutcome::Inactive)));

        // A zero TTL is already past by the time it is read back.
        plugin.store(key, CachedOutcome::Inactive, Duration::ZERO);
        assert!(plugin.cached(&key).is_none());
    }

    #[test]
    fn the_cache_does_not_grow_past_its_bound() {
        let params = format!(
            "{{{}, cache-max-entries: 4}}",
            complete().trim_matches(['{', '}'])
        );
        let plugin = plugin(&params).unwrap();

        for index in 0..50u8 {
            plugin.store([index; 32], CachedOutcome::Inactive, Duration::from_secs(60));
        }

        assert!(plugin.cache.lock().unwrap().len() <= 4);
    }
}
