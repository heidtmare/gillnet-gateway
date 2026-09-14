//! `jwt-plugin`: HS256 tokens verified against a shared secret.
//!
//! Self-contained verification -- no call out to a provider, so nothing to be
//! unavailable and nothing to cache. The trade is that a token stays valid
//! until it expires; there is no revocation. Use `oauth2-plugin` where that
//! matters.

use std::sync::Arc;

use awc::Client;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value as Json};

use crate::auth::AuthOutcome;
use crate::config::PluginConfig;
use crate::plugins::{self, AuthPlugin, Authenticating};

pub const KIND: &str = "jwt-plugin";

pub struct JwtPlugin {
    name: String,
    header_keys: Vec<String>,
    key: DecodingKey,
    validation: Validation,
    roles_claim: String,
}

pub fn build(config: &PluginConfig) -> Result<JwtPlugin, String> {
    let secret = plugins::string(&config.params, "secret")?
        .ok_or_else(|| format!("{KIND} requires 'secret'"))?;
    if secret.is_empty() {
        return Err(format!("{KIND} 'secret' must not be empty"));
    }

    let mut validation = Validation::new(Algorithm::HS256);
    if let Some(issuer) = plugins::string(&config.params, "issuer")? {
        validation.set_issuer(&[issuer]);
    }
    match plugins::string(&config.params, "audience")? {
        Some(audience) => validation.set_audience(&[audience]),
        // jsonwebtoken validates `aud` by default; without a configured
        // audience that would reject every token carrying one.
        None => validation.validate_aud = false,
    }

    Ok(JwtPlugin {
        name: config.name.to_owned(),
        header_keys: plugins::string_list(&config.params, "keys")?,
        key: DecodingKey::from_secret(secret.as_bytes()),
        validation,
        roles_claim: plugins::string(&config.params, "roles-claim")?
            .unwrap_or_else(|| "roles".to_owned()),
    })
}

impl AuthPlugin for JwtPlugin {
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

    fn authenticate<'a>(&'a self, token: &'a str, _client: &'a Client) -> Authenticating<'a> {
        let verified = decode::<Map<String, Json>>(token, &self.key, &self.validation)
            .map(|data| Arc::new(data.claims))
            .map_err(|error| {
                AuthOutcome::Unauthorized(format!(
                    "invalid token for '{}': {:?}",
                    self.name,
                    error.kind()
                ))
            });

        Box::pin(async move { verified })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    fn plugin(params: &str) -> Result<JwtPlugin, String> {
        build(&PluginConfig {
            name: "test-jwt".to_owned(),
            plugin_id: KIND.to_owned(),
            params: yaml_serde::from_str(params).expect("invalid test params"),
        })
    }

    fn token(claims: Json) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"shh"),
        )
        .expect("could not sign the test token")
    }

    fn verify(plugin: &JwtPlugin, token: &str) -> Result<Arc<Map<String, Json>>, AuthOutcome> {
        futures_util::future::FutureExt::now_or_never(
            plugin.authenticate(token, &Client::default()),
        )
        .expect("verification is synchronous and must resolve immediately")
    }

    fn far_future() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600
    }

    #[test]
    fn a_plugin_with_no_usable_secret_is_refused() {
        assert!(plugin("issuer: https://auth.example.com").is_err());
        assert!(plugin("secret: ''").is_err());
        assert!(plugin("secret: shh").is_ok());
    }

    #[test]
    fn roles_default_to_the_roles_claim() {
        assert_eq!(plugin("secret: shh").unwrap().roles_claim(), Some("roles"));
        assert_eq!(
            plugin("{secret: shh, roles-claim: groups}")
                .unwrap()
                .roles_claim(),
            Some("groups")
        );
    }

    #[test]
    fn a_token_signed_with_the_configured_secret_verifies() {
        let plugin = plugin("secret: shh").unwrap();
        let claims = verify(&plugin, &token(json!({"sub": "u1", "exp": far_future()})))
            .expect("a correctly signed token must verify");

        assert_eq!(claims["sub"], json!("u1"));
    }

    #[test]
    fn a_token_signed_with_another_secret_is_refused() {
        let plugin = plugin("secret: different").unwrap();
        let outcome = verify(&plugin, &token(json!({"sub": "u1", "exp": far_future()})));

        assert!(matches!(outcome, Err(AuthOutcome::Unauthorized(_))));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let plugin = plugin("secret: shh").unwrap();
        let outcome = verify(&plugin, &token(json!({"sub": "u1", "exp": 1})));

        assert!(matches!(outcome, Err(AuthOutcome::Unauthorized(_))));
    }

    #[test]
    fn an_audience_is_enforced_only_when_one_is_configured() {
        let stamped = token(json!({"sub": "u1", "aud": "gillnet", "exp": far_future()}));

        // Unconfigured: a token carrying an audience must still pass, or every
        // provider that stamps one would be rejected out of the box.
        assert!(verify(&plugin("secret: shh").unwrap(), &stamped).is_ok());

        let configured = plugin("{secret: shh, audience: gillnet}").unwrap();
        assert!(verify(&configured, &stamped).is_ok());

        let other = plugin("{secret: shh, audience: something-else}").unwrap();
        assert!(verify(&other, &stamped).is_err());
    }

    #[test]
    fn an_issuer_is_enforced_when_configured() {
        let plugin = plugin("{secret: shh, issuer: 'https://auth.example.com'}").unwrap();

        let right = token(json!({"iss": "https://auth.example.com", "exp": far_future()}));
        let wrong = token(json!({"iss": "https://evil.example.com", "exp": far_future()}));

        assert!(verify(&plugin, &right).is_ok());
        assert!(verify(&plugin, &wrong).is_err());
    }
}
