//! The plugin types a gateway config can declare.
//!
//! Each `type:` is one module, and a module is self-contained: it parses its
//! own `params`, holds its own state, and decides what it does with a request.
//!
//! They come in two families. The three auth plugins decide what a *credential*
//! means and are reached through [`AuthPlugin`], so adding a fourth means
//! adding a file and a line in [`build`] rather than editing a match arm in
//! four places. [`wasm`] is the other: a filter that inspects and edits a
//! request the guards have already cleared, dispatched by the registry because
//! it needs the shared WebAssembly engine.
//!
//! [`session`] is the seam between two of them. An `oauth2-plugin` that has
//! asked the provider once mints a cookie saying so, and a `jwt-plugin` on
//! another route verifies that cookie the way it verifies any other token --
//! so a browser pays for introspection at the door and not on every request
//! behind it.
//!
//! What stays out here is anything a *route* decides rather than a plugin:
//! required roles and `insert-headers` belong to [`crate::auth::RouteGuard`],
//! which wraps a plugin with the bindings one route gave it.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::web;
use awc::Client;
use serde_json::{Map, Value as Json};
use yaml_serde::Value as Yaml;

use crate::auth::AuthOutcome;
use crate::config::PluginConfig;

// The file names match the `type:` strings they implement, which is worth one
// `#[path]` each: a config says `type: jwt-plugin` and the code is in
// jwt-plugin.rs, with nothing to look up in between.
#[path = "jwt-plugin.rs"]
pub mod jwt;
#[path = "oauth2-plugin.rs"]
pub mod oauth2;
#[path = "testing-plugin.rs"]
pub mod testing;
#[path = "token-plugin.rs"]
pub mod token;
#[path = "wasm-plugin.rs"]
pub mod wasm;

// Not a `type:` of its own, so no `#[path]`: the session cookie two plugins
// share, factored out so the one that mints it and the one that reads it
// cannot drift apart on a flag or a claim.
pub mod session;

/// Every `type:` the gateway understands, in the order a config is likely to
/// meet them. Assembled from the modules themselves so a new plugin appears in
/// the error a typo produces without anyone remembering to add it.
pub const KINDS: [&str; 5] = [
    token::KIND,
    jwt::KIND,
    oauth2::KIND,
    testing::KIND,
    wasm::KIND,
];

/// One authentication plugin: the part of a route's auth that a plugin type
/// owns, as opposed to the part a route configures.
///
/// `Send + Sync` because the registry holding these is shared across worker
/// threads. The returned future deliberately is *not* `Send`: the HTTP client
/// a plugin may call out with is per-worker and not `Send` either.
pub trait AuthPlugin: Send + Sync {
    /// The `type:` this plugin was declared with.
    fn kind(&self) -> &'static str;

    /// The `name:` it was declared under, used in the errors a caller sees.
    fn name(&self) -> &str;

    /// Headers this plugin will read a credential out of, beyond the standard
    /// `Authorization`. The proxy strips these before forwarding unless the
    /// route opted into `forward-token`.
    fn header_keys(&self) -> &[String];

    /// Cookies this plugin will read a credential out of, tried after every
    /// header. Stripped from the forwarded `Cookie` header on the same terms
    /// as [`AuthPlugin::header_keys`], leaving the request's other cookies
    /// alone -- a session cookie is the gateway's business, the rest are the
    /// application's.
    fn cookie_keys(&self) -> &[String] {
        &[]
    }

    /// The session cookie this plugin *mints*, if it mints one. Reported
    /// separately from [`AuthPlugin::cookie_keys`] because minting and
    /// accepting are different things: an `oauth2-plugin` issues a cookie it
    /// will never take back as a credential, since only the provider gets to
    /// say whether a token is still live.
    fn session_cookie(&self) -> Option<&session::SessionCookie> {
        None
    }

    /// Which claim holds the caller's roles, or `None` for a plugin that
    /// confirms a credential without learning anything about who presented it.
    /// A route cannot require roles of a plugin that answers `None`.
    fn roles_claim(&self) -> Option<&str>;

    /// Verifies the credential and returns the claims it vouches for, or the
    /// outcome to send back. A plugin with no claims to offer returns an empty
    /// map rather than failing.
    fn authenticate<'a>(&'a self, credential: Credential<'a>, client: &'a Client)
        -> Authenticating<'a>;

    /// Response headers to add on the way back, now that this plugin has
    /// verified who is calling -- in practice the `Set-Cookie` that starts a
    /// session. Handed the credential as well as the claims so a plugin can
    /// decline to re-issue a cookie the request already carries.
    fn issue<'a>(
        &self,
        credential: Credential<'a>,
        claims: &Map<String, Json>,
    ) -> Vec<(String, String)> {
        match self.session_cookie() {
            Some(cookie) => cookie.issue(credential, claims),
            None => Vec::new(),
        }
    }

    /// HTTP endpoints this plugin needs mounted on the proxy listener. Almost
    /// nothing wants this; `testing-plugin` does, because the claim sets it
    /// serves have to be posted from somewhere.
    fn endpoint(&self) -> Option<Endpoint> {
        None
    }
}

/// A scope a plugin asks the proxy listener to mount for it. The routes are a
/// closure so a plugin can register whatever it likes without this module
/// knowing what they are.
#[derive(Clone)]
pub struct Endpoint {
    /// The plugin that asked for it, for the startup warning and `describe`.
    pub plugin: String,
    pub path: String,
    pub configure: Arc<dyn Fn(&mut web::ServiceConfig) + Send + Sync>,
}

/// What a request offered a plugin, as the route's extraction found it.
///
/// Two fields rather than one because they answer different questions. The
/// `token` is what this plugin must verify; the `session` is what the caller
/// already carried, which a plugin may consult even when the token came from
/// somewhere else -- that is how a `testing-plugin` takes a live session as
/// the baseline its registered overrides are layered onto.
#[derive(Clone, Copy)]
pub struct Credential<'a> {
    pub token: &'a str,
    pub session: Option<&'a str>,
}

/// The future [`AuthPlugin::authenticate`] returns. Boxed because a trait with
/// an `async fn` cannot be used behind `dyn`, which is how plugins are stored.
pub type Authenticating<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<Map<String, Json>>, AuthOutcome>> + 'a>>;

/// Builds the plugin a `plugins:` entry names. WebAssembly plugins are not
/// built here -- they are not an auth kind and the registry dispatches them
/// before this is reached -- but they are listed in [`KINDS`] so a typo names
/// every type the gateway actually understands.
pub fn build(config: &PluginConfig) -> Result<Arc<dyn AuthPlugin>, String> {
    match config.plugin_id.as_str() {
        token::KIND => token::build(config).map(into_plugin),
        jwt::KIND => jwt::build(config).map(into_plugin),
        oauth2::KIND => oauth2::build(config).map(into_plugin),
        testing::KIND => testing::build(config).map(into_plugin),
        other => Err(format!(
            "unknown plugin type '{other}' (expected {})",
            known_kinds()
        )),
    }
}

fn into_plugin<P: AuthPlugin + 'static>(plugin: P) -> Arc<dyn AuthPlugin> {
    Arc::new(plugin)
}

fn known_kinds() -> String {
    let quoted: Vec<String> = KINDS.iter().map(|kind| format!("'{kind}'")).collect();

    match quoted.split_last() {
        Some((last, [])) => last.to_owned(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    }
}

/// Reading a plugin's `params`. Shared by every plugin type, including the
/// WebAssembly one, so a value is spelled and rejected the same way wherever
/// it appears.
pub fn string(params: &HashMap<String, Yaml>, key: &str) -> Result<Option<String>, String> {
    match params.get(key) {
        Some(Yaml::String(raw)) => expand_env(raw).map(Some),
        Some(_) => Err(format!("'{key}' must be a string")),
        None => Ok(None),
    }
}

pub fn string_list(params: &HashMap<String, Yaml>, key: &str) -> Result<Vec<String>, String> {
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

pub fn number(params: &HashMap<String, Yaml>, key: &str, default: u64) -> Result<u64, String> {
    match params.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("'{key}' must be a positive integer")),
        None => Ok(default),
    }
}

pub fn flag(params: &HashMap<String, Yaml>, key: &str) -> Result<bool, String> {
    flag_or(params, key, false)
}

/// A flag whose absence does not mean "off". Cookie attributes are the reason:
/// `secure` and `http-only` default to on, so forgetting them hardens the
/// cookie rather than quietly exposing it.
pub fn flag_or(params: &HashMap<String, Yaml>, key: &str, default: bool) -> Result<bool, String> {
    match params.get(key) {
        Some(Yaml::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("'{key}' must be true or false")),
        None => Ok(default),
    }
}

/// A nested block of `params`, such as `session-cookie:`. Handed back as a
/// `HashMap` so every reader above applies to it unchanged.
pub fn mapping(
    params: &HashMap<String, Yaml>,
    key: &str,
) -> Result<Option<HashMap<String, Yaml>>, String> {
    match params.get(key) {
        Some(Yaml::Mapping(mapping)) => mapping
            .iter()
            .map(|(name, value)| match name.as_str() {
                Some(name) => Ok((name.to_owned(), value.to_owned())),
                None => Err(format!("'{key}' keys must be strings")),
            })
            .collect::<Result<HashMap<_, _>, String>>()
            .map(Some),
        Some(_) => Err(format!("'{key}' must be a mapping")),
        None => Ok(None),
    }
}

/// Expands `$VAR` and `${VAR}`. An unset variable is an error rather than an
/// empty string, so a missing secret cannot silently become a valid credential.
pub fn expand_env(raw: &str) -> Result<String, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn params(yaml: &str) -> HashMap<String, Yaml> {
        yaml_serde::from_str(yaml).expect("invalid test params")
    }

    #[test]
    fn a_typo_names_every_type_the_gateway_understands() {
        let Err(error) = build(&PluginConfig {
            name: "oops".to_owned(),
            plugin_id: "jwt".to_owned(),
            params: HashMap::new(),
        }) else {
            panic!("'jwt' is not a plugin type and must not build");
        };

        for kind in KINDS {
            assert!(error.contains(kind), "'{kind}' missing from: {error}");
        }
    }

    #[test]
    fn an_unset_variable_is_an_error_not_an_empty_secret() {
        std::env::set_var("GILLNET_TEST_SECRET", "s3cret");

        assert_eq!(expand_env("$GILLNET_TEST_SECRET").unwrap(), "s3cret");
        assert_eq!(expand_env("pre-${GILLNET_TEST_SECRET}-post").unwrap(), "pre-s3cret-post");
        assert!(expand_env("$GILLNET_TEST_DEFINITELY_UNSET").is_err());
    }

    #[test]
    fn a_dollar_naming_nothing_is_left_alone() {
        // Only a `$` with no name after it is literal. `$5` names a variable
        // called `5`, and an unset one is an error like any other -- a config
        // value is never silently emptied.
        assert_eq!(expand_env("costs $ 5").unwrap(), "costs $ 5");
        assert_eq!(expand_env("100%").unwrap(), "100%");
        assert!(expand_env("costs $5").is_err());
        assert!(expand_env("${GILLNET_TEST_SECRET").is_err());
    }

    #[test]
    fn a_single_string_reads_as_a_one_entry_list() {
        assert_eq!(string_list(&params("keys: api-key"), "keys").unwrap(), ["api-key"]);
        assert_eq!(
            string_list(&params("keys: [a, b]"), "keys").unwrap(),
            ["a", "b"]
        );
        assert!(string_list(&params("keys: 7"), "keys").is_err());
    }

    #[test]
    fn a_missing_value_falls_back_to_the_default() {
        assert_eq!(number(&params("other: 1"), "fuel", 99).unwrap(), 99);
        assert_eq!(number(&params("fuel: 5"), "fuel", 99).unwrap(), 5);
        assert!(number(&params("fuel: nope"), "fuel", 99).is_err());
        assert!(!flag(&params("other: true"), "fail-open").unwrap());
        assert!(flag(&params("fail-open: true"), "fail-open").unwrap());
        assert!(flag(&params("fail-open: yes-ish"), "fail-open").is_err());
    }
}
