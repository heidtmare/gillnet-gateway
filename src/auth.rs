//! Binding a plugin to a route, and enforcing the result.
//!
//! A plugin type decides what a credential *means* -- that lives in
//! [`crate::plugins`]. What a particular route asks of it is here: which roles
//! it requires and which identity headers it wants rendered from the verified
//! claims. The same plugin can therefore guard one route for `admin` and
//! another for `user` without being configured twice.

use std::collections::HashSet;
use std::sync::Arc;

use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use awc::Client;
use serde_json::{Map, Value as Json};
use yaml_serde::Value as Yaml;

use crate::config::PluginReference;
use crate::plugins::{self, AuthPlugin};
use crate::testing::ClaimOverrides;

/// One plugin as a single route uses it.
#[derive(Clone)]
pub struct RouteGuard {
    plugin: Arc<dyn AuthPlugin>,
    required_roles: Vec<String>,
    insert_headers: Vec<(String, String)>,
}

/// `Debug` so a failing test can say which outcome it got; the variants carry
/// only messages already meant for a caller, never a credential.
#[derive(Debug)]
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
    overrides: &ClaimOverrides,
) -> AuthOutcome {
    let mut identity = Vec::new();

    for guard in guards {
        match guard.check(headers, client, overrides).await {
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

/// Headers a guard on this route would read a credential out of: the standard
/// `Authorization`, plus whatever `keys:` each plugin was configured with.
/// Stripped before forwarding unless the route opts into `forward-token`.
///
/// An unguarded route yields nothing -- the gateway never looked at a
/// credential there, so it has none to withhold and stays a plain pass-through.
pub fn credential_header_names(guards: &[RouteGuard]) -> HashSet<String> {
    if guards.is_empty() {
        return HashSet::new();
    }

    std::iter::once("authorization".to_owned())
        .chain(
            guards
                .iter()
                .flat_map(|guard| guard.plugin.header_keys())
                .map(|key| key.to_ascii_lowercase()),
        )
        .collect()
}

impl RouteGuard {
    pub fn build(
        plugin: Arc<dyn AuthPlugin>,
        required_roles: Vec<String>,
        insert_headers: Vec<(String, String)>,
    ) -> Result<Self, String> {
        let name = plugin.name();

        // A plugin with no roles claim learned nothing about who presented the
        // credential, so a role requirement on it could never be met. Saying so
        // at startup beats a route that quietly rejects everyone.
        if !required_roles.is_empty() && plugin.roles_claim().is_none() {
            return Err(format!(
                "plugin '{name}' is a {} and carries no claims, so it cannot require roles",
                plugin.kind()
            ));
        }
        // Validated as a header *name*: `HeaderValue` would accept a space,
        // which is legal in a value and not in a name, and the bad name would
        // only surface when a request tried to set it.
        for (header, _) in &insert_headers {
            if HeaderName::from_bytes(header.as_bytes()).is_err() {
                return Err(format!("plugin '{name}' has an invalid header name '{header}'"));
            }
        }

        Ok(Self {
            plugin,
            required_roles,
            insert_headers,
        })
    }

    pub fn from_reference(
        reference: &PluginReference,
        plugin: Arc<dyn AuthPlugin>,
    ) -> Result<Self, String> {
        let params = reference.params.clone().unwrap_or_default();
        let roles = plugins::string_list(&params, "roles")?;

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

        Self::build(plugin, roles, insert_headers)
    }

    pub fn name(&self) -> &str {
        self.plugin.name()
    }

    pub fn kind(&self) -> &'static str {
        self.plugin.kind()
    }

    pub fn required_roles(&self) -> &[String] {
        &self.required_roles
    }

    /// Header name/template pairs only; the values are rendered per request
    /// from verified claims and are never stored here.
    pub fn insert_headers(&self) -> &[(String, String)] {
        &self.insert_headers
    }

    /// Extract, verify, authorize, render -- the same four steps whatever the
    /// plugin type, because everything type-specific happens inside
    /// `authenticate`.
    async fn check(
        &self,
        headers: &HeaderMap,
        client: &Client,
        overrides: &ClaimOverrides,
    ) -> Result<Vec<(String, String)>, AuthOutcome> {
        let Some(token) = extract_token(headers, self.plugin.header_keys()) else {
            return Err(AuthOutcome::Unauthorized(format!(
                "missing credentials for '{}'",
                self.name()
            )));
        };

        let claims = self.plugin.authenticate(&token, client, overrides).await?;

        self.authorize(&claims)?;
        self.render_identity(&claims)
    }

    fn authorize(&self, claims: &Map<String, Json>) -> Result<(), AuthOutcome> {
        // `build` refuses a role requirement on a plugin with no roles claim,
        // so there is nothing left to check here.
        let Some(roles_claim) = self.plugin.roles_claim() else {
            return Ok(());
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginConfig;
    use crate::plugins::{jwt, token};
    use actix_web::http::header::{HeaderName, HeaderValue};
    use serde_json::json;

    fn plugin(kind: &str, params: &str) -> Arc<dyn AuthPlugin> {
        plugins::build(&PluginConfig {
            name: format!("test-{kind}"),
            plugin_id: kind.to_owned(),
            params: yaml_serde::from_str(params).expect("invalid test params"),
        })
        .expect("the test plugin should build")
    }

    fn guard(kind: &str, params: &str, reference: &str) -> Result<RouteGuard, String> {
        RouteGuard::from_reference(
            &PluginReference {
                name: format!("test-{kind}"),
                params: Some(yaml_serde::from_str(reference).expect("invalid test reference")),
            },
            plugin(kind, params),
        )
    }

    fn claims(value: Json) -> Map<String, Json> {
        value.as_object().unwrap().to_owned()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_static(name),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn a_plugin_carrying_no_claims_cannot_be_asked_for_roles() {
        let Err(error) = guard(token::KIND, "tokens: [good]", "roles: [admin]") else {
            panic!("a shared secret cannot satisfy a role requirement");
        };
        assert!(error.contains(token::KIND), "unexpected: {error}");

        // Without roles the same plugin binds fine.
        assert!(guard(token::KIND, "tokens: [good]", "{}").is_ok());
    }

    #[test]
    fn a_guard_takes_its_name_from_the_plugin_it_wraps() {
        let guard = guard(jwt::KIND, "secret: shh", "{}").unwrap();

        assert_eq!(guard.name(), "test-jwt-plugin");
        assert_eq!(guard.kind(), jwt::KIND);
    }

    #[test]
    fn an_unusable_header_name_is_refused_at_startup() {
        // Built directly rather than through YAML so a name containing a
        // newline -- the one that would splice headers -- can be tested at all.
        let bound = |header: &str| {
            RouteGuard::build(
                plugin(jwt::KIND, "secret: shh"),
                Vec::new(),
                vec![(header.to_owned(), "{sub}".to_owned())],
            )
        };

        // A space is legal in a header value and not in a name, so validating
        // the name as a value would let these through to fail per request.
        for bad in ["bad header", "", "  ", "x:user", "x\nuser", "x\r\nX-Admin: true"] {
            assert!(bound(bad).is_err(), "{bad:?} is not a usable header name");
        }

        assert!(bound("x-user").is_ok());
        assert!(bound("USER-ID").is_ok());
    }

    #[test]
    fn required_roles_must_all_be_granted() {
        let guard = guard(jwt::KIND, "secret: shh", "roles: [admin, ops]").unwrap();

        assert!(guard.authorize(&claims(json!({"roles": ["admin", "ops"]}))).is_ok());

        let missing = guard.authorize(&claims(json!({"roles": ["admin"]})));
        let Err(AuthOutcome::Forbidden(message)) = missing else {
            panic!("a missing role must be forbidden");
        };
        assert!(message.contains("ops"), "unexpected: {message}");
    }

    #[test]
    fn a_space_delimited_scope_reads_as_a_role_list() {
        // OAuth2 sends `scope` as one string; a JWT sends an array. Both have
        // to work or the same route config would behave differently per plugin.
        assert_eq!(
            roles(&claims(json!({"scope": "read write"})), "scope"),
            ["read", "write"]
        );
        assert_eq!(
            roles(&claims(json!({"roles": ["read", "write"]})), "roles"),
            ["read", "write"]
        );
        assert!(roles(&claims(json!({"roles": 7})), "roles").is_empty());
    }

    #[test]
    fn identity_headers_render_from_verified_claims() {
        let guard = guard(
            jwt::KIND,
            "secret: shh",
            "insert-headers: {'x-user': '{sub}', 'x-email': '{email}', 'x-age': 'n={age}'}",
        )
        .unwrap();

        let rendered = guard
            .render_identity(&claims(json!({"sub": "u1", "email": "a@b.c", "age": 41})))
            .unwrap();

        assert_eq!(
            rendered,
            [
                ("x-user".to_owned(), "u1".to_owned()),
                ("x-email".to_owned(), "a@b.c".to_owned()),
                ("x-age".to_owned(), "n=41".to_owned()),
            ]
        );
    }

    #[test]
    fn a_header_referencing_an_absent_claim_is_skipped() {
        let guard = guard(
            jwt::KIND,
            "secret: shh",
            "insert-headers: {'x-user': '{sub}', 'x-missing': '{nope}'}",
        )
        .unwrap();

        let rendered = guard.render_identity(&claims(json!({"sub": "u1"}))).unwrap();
        assert_eq!(rendered, [("x-user".to_owned(), "u1".to_owned())]);
    }

    #[test]
    fn a_claim_that_would_splice_headers_is_refused() {
        let guard = guard(jwt::KIND, "secret: shh", "insert-headers: {'x-user': '{sub}'}").unwrap();

        let spliced = guard.render_identity(&claims(json!({"sub": "u1\r\nX-Admin: true"})));
        assert!(matches!(spliced, Err(AuthOutcome::Forbidden(_))));
    }

    #[test]
    fn a_bearer_token_wins_over_a_configured_key_header() {
        let keys = ["api-key".to_owned()];

        assert_eq!(
            extract_token(&headers(&[("authorization", "Bearer abc")]), &keys),
            Some("abc".to_owned())
        );
        // Lowercase `bearer` is equally legal and some clients send it.
        assert_eq!(
            extract_token(&headers(&[("authorization", "bearer abc")]), &keys),
            Some("abc".to_owned())
        );
        assert_eq!(
            extract_token(
                &headers(&[("authorization", "Bearer abc"), ("api-key", "xyz")]),
                &keys
            ),
            Some("abc".to_owned())
        );
        assert_eq!(
            extract_token(&headers(&[("api-key", "xyz")]), &keys),
            Some("xyz".to_owned())
        );
        // An empty credential is no credential.
        assert_eq!(extract_token(&headers(&[("authorization", "Bearer ")]), &keys), None);
        assert_eq!(extract_token(&headers(&[("api-key", "  ")]), &keys), None);
        assert_eq!(extract_token(&HeaderMap::new(), &keys), None);
    }

    #[test]
    fn a_guarded_route_withholds_the_credential_it_consumed() {
        let guard = guard(token::KIND, "{tokens: [good], keys: [Api-Key]}", "{}").unwrap();
        let names = credential_header_names(std::slice::from_ref(&guard));

        assert!(names.contains("authorization"));
        assert!(names.contains("api-key"));

        // An unguarded route consumed nothing, so it withholds nothing.
        assert!(credential_header_names(&[]).is_empty());
    }

    #[test]
    fn injected_headers_are_reported_lowercase_for_matching() {
        let guard = guard(jwt::KIND, "secret: shh", "insert-headers: {'USER-ID': '{sub}'}").unwrap();

        let names = injected_header_names(std::slice::from_ref(&guard));
        assert!(names.contains("user-id"));
    }
}
