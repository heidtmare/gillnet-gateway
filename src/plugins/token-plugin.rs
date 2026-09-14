//! `token-plugin`: a fixed list of shared secrets, compared in constant time.
//!
//! The simplest thing that can guard a route, and the least informative: a
//! shared secret says a caller knows the secret and nothing whatever about who
//! they are. That is why this plugin has no roles claim, and why a route that
//! tries to require roles of it is rejected at startup.

use std::sync::Arc;

use awc::Client;
use serde_json::Map;

use crate::auth::AuthOutcome;
use crate::config::PluginConfig;
use crate::plugins::{self, AuthPlugin, Authenticating, Credential};

pub const KIND: &str = "token-plugin";

pub struct TokenPlugin {
    name: String,
    header_keys: Vec<String>,
    tokens: Vec<String>,
}

pub fn build(config: &PluginConfig) -> Result<TokenPlugin, String> {
    let tokens = plugins::string_list(&config.params, "tokens")?;

    if tokens.is_empty() {
        return Err(format!("{KIND} requires a non-empty 'tokens' list"));
    }
    // An empty entry would match a caller that sent an empty header value.
    if tokens.iter().any(String::is_empty) {
        return Err(format!("{KIND} 'tokens' must not contain empty values"));
    }

    Ok(TokenPlugin {
        name: config.name.to_owned(),
        header_keys: plugins::string_list(&config.params, "keys")?,
        tokens,
    })
}

impl AuthPlugin for TokenPlugin {
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
        None
    }

    fn authenticate<'a>(
        &'a self,
        credential: Credential<'a>,
        _client: &'a Client,
    ) -> Authenticating<'a> {
        let matched = self.tokens.iter().any(|candidate| {
            constant_time_eq(candidate.as_bytes(), credential.token.as_bytes())
        });

        Box::pin(async move {
            if matched {
                // Verified, but there is no identity here to hand on.
                Ok(Arc::new(Map::new()))
            } else {
                Err(AuthOutcome::Unauthorized(format!(
                    "invalid credentials for '{}'",
                    self.name
                )))
            }
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(params: &str) -> Result<TokenPlugin, String> {
        build(&PluginConfig {
            name: "test-token".to_owned(),
            plugin_id: KIND.to_owned(),
            params: yaml_serde::from_str(params).expect("invalid test params"),
        })
    }

    #[test]
    fn a_plugin_with_nothing_to_check_against_is_refused() {
        assert!(plugin("keys: [api-key]").is_err());
        assert!(plugin("tokens: []").is_err());
        assert!(plugin("tokens: ['']").is_err());
        assert!(plugin("tokens: [good]").is_ok());
    }

    #[test]
    fn a_shared_secret_carries_no_identity() {
        let plugin = plugin("tokens: [good]").unwrap();

        // No roles claim is what stops a route requiring roles of this plugin.
        assert_eq!(plugin.roles_claim(), None);
        assert_eq!(plugin.kind(), KIND);
    }

    #[test]
    fn comparison_does_not_exit_early() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        // A shorter candidate sharing a prefix must not compare equal.
        assert!(!constant_time_eq(b"secret", b"sec"));
        assert!(constant_time_eq(b"", b""));
    }
}
