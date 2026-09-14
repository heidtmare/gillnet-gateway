//! The session cookie: one round-trip to the provider, remembered.
//!
//! An `oauth2-plugin` asks the authorization provider about a token and learns
//! who is calling. That answer is worth keeping: this mints it into an HS256
//! token and hands it back as a `Set-Cookie`, so a browser that authenticates
//! once at a login route carries proof of it to every route behind. A
//! `jwt-plugin` on those routes verifies the cookie exactly as it verifies a
//! bearer token, because it *is* one -- same algorithm, same secret, same
//! issuer and audience checks. There is no second format to keep in step.
//!
//! The trade is the one `jwt-plugin` always makes and states plainly: a minted
//! session is not revocable. It stops working when it expires and not before,
//! so `ttl-seconds` is the window in which a revoked token still opens doors.
//! It is capped by the provider's own `exp` -- a session never outlives the
//! credential it was minted from -- and a route that cannot tolerate the gap
//! should keep guarding with `oauth2-plugin`, which asks every time.
//!
//! The cookie is `HttpOnly` and `Secure` unless a config says otherwise, which
//! means the default cannot be read by script and will not travel in the clear.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Map, Value as Json};
use yaml_serde::Value as Yaml;

use crate::plugins::{self, Credential};

/// The `params` key a plugin declares its cookie under.
pub const PARAM: &str = "session-cookie";

pub const DEFAULT_NAME: &str = "gillnet-session";
const DEFAULT_TTL_SECONDS: u64 = 3600;

/// Introspection fields that describe the *lookup* rather than the caller.
/// Carrying `active: true` into a session token would be worse than noise: it
/// reads like a liveness claim that nothing is checking any more.
const NOT_IDENTITY: [&str; 2] = ["active", "token_type"];

pub struct SessionCookie {
    name: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    ttl: i64,
    issuer: Option<String>,
    audience: Option<String>,
    /// Everything after `name=value; Max-Age=n`, rendered once at startup
    /// because it never varies per request.
    attributes: String,
}

/// Reads a `session-cookie:` block, or `None` when the plugin was not given
/// one. `kind` only names the plugin in errors.
pub fn build(
    params: &HashMap<String, Yaml>,
    kind: &str,
) -> Result<Option<SessionCookie>, String> {
    let Some(block) = plugins::mapping(params, PARAM)? else {
        return Ok(None);
    };

    // The secret is what makes the cookie a credential rather than a note, and
    // it has to be the one the `jwt-plugin` reading it was given.
    let secret = plugins::string(&block, "secret")?
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| format!("{kind} '{PARAM}' requires a non-empty 'secret'"))?;

    let name = plugins::string(&block, "name")?.unwrap_or_else(|| DEFAULT_NAME.to_owned());
    if !is_cookie_name(&name) {
        return Err(format!("{kind} '{PARAM}' has an invalid cookie name '{name}'"));
    }

    let ttl = plugins::number(&block, "ttl-seconds", DEFAULT_TTL_SECONDS)?;
    if ttl == 0 {
        return Err(format!("{kind} '{PARAM}' 'ttl-seconds' must be greater than zero"));
    }

    let issuer = plugins::string(&block, "issuer")?;
    let audience = plugins::string(&block, "audience")?;

    let mut validation = Validation::new(Algorithm::HS256);
    if let Some(issuer) = &issuer {
        validation.set_issuer(&[issuer]);
    }
    match &audience {
        Some(audience) => validation.set_audience(&[audience]),
        // Same reasoning as `jwt-plugin`: without a configured audience,
        // validating one would reject every token a provider stamped.
        None => validation.validate_aud = false,
    }

    Ok(Some(SessionCookie {
        encoding: EncodingKey::from_secret(secret.as_bytes()),
        decoding: DecodingKey::from_secret(secret.as_bytes()),
        validation,
        ttl: ttl as i64,
        issuer,
        audience,
        attributes: attributes(&block, kind)?,
        name,
    }))
}

/// Renders the fixed part of the `Set-Cookie`, rejecting anything that would
/// not survive being written into a header.
fn attributes(block: &HashMap<String, Yaml>, kind: &str) -> Result<String, String> {
    let path = plugins::string(block, "path")?.unwrap_or_else(|| "/".to_owned());
    let domain = plugins::string(block, "domain")?;
    let secure = plugins::flag_or(block, "secure", true)?;
    let http_only = plugins::flag_or(block, "http-only", true)?;

    let same_site = match plugins::string(block, "same-site")?.as_deref() {
        None => "Lax".to_owned(),
        Some(value) if value.eq_ignore_ascii_case("strict") => "Strict".to_owned(),
        Some(value) if value.eq_ignore_ascii_case("lax") => "Lax".to_owned(),
        Some(value) if value.eq_ignore_ascii_case("none") => "None".to_owned(),
        Some(other) => {
            return Err(format!(
                "{kind} '{PARAM}' 'same-site' must be Strict, Lax or None, not '{other}'"
            ))
        }
    };
    // A browser drops `SameSite=None` without `Secure`, so the config as
    // written would produce no session at all. Better to say so at startup.
    if same_site == "None" && !secure {
        return Err(format!(
            "{kind} '{PARAM}' 'same-site: None' requires 'secure: true'"
        ));
    }

    for (label, value) in [("path", Some(&path)), ("domain", domain.as_ref())] {
        if value.is_some_and(|value| !is_attribute_value(value)) {
            return Err(format!("{kind} '{PARAM}' has an invalid '{label}'"));
        }
    }

    let mut attributes = format!("; Path={path}");
    if let Some(domain) = &domain {
        attributes.push_str(&format!("; Domain={domain}"));
    }
    attributes.push_str(&format!("; SameSite={same_site}"));
    if http_only {
        attributes.push_str("; HttpOnly");
    }
    if secure {
        attributes.push_str("; Secure");
    }
    Ok(attributes)
}

impl SessionCookie {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The claims this cookie vouches for, or `None` if it does not verify,
    /// has expired, or was minted for a different issuer or audience.
    pub fn claims(&self, cookie: &str) -> Option<Map<String, Json>> {
        decode::<Map<String, Json>>(cookie, &self.decoding, &self.validation)
            .ok()
            .map(|data| data.claims)
    }

    /// The `Set-Cookie` for the identity a plugin just verified.
    ///
    /// Nothing is issued when the request already carries a session cookie
    /// that still verifies: re-stamping one on every request would put a
    /// `Set-Cookie` on every response for no gain. The consequence is that a
    /// session runs out rather than sliding -- it is refreshed by presenting
    /// the original credential again, once the old cookie stops verifying.
    pub fn issue(
        &self,
        credential: Credential<'_>,
        claims: &Map<String, Json>,
    ) -> Vec<(String, String)> {
        if credential
            .session
            .is_some_and(|cookie| self.claims(cookie).is_some())
        {
            return Vec::new();
        }

        match self.mint(claims) {
            Ok(value) => vec![("set-cookie".to_owned(), value)],
            // A request that authenticated is not worth failing over a cookie
            // that could not be signed; the caller simply gets no session.
            Err(error) => {
                eprintln!("could not mint session cookie '{}': {error}", self.name);
                Vec::new()
            }
        }
    }

    fn mint(&self, claims: &Map<String, Json>) -> Result<String, String> {
        let now = unix_now();
        let mut payload = claims.clone();

        for claim in NOT_IDENTITY {
            payload.remove(claim);
        }

        // Capped by the credential's own expiry: a session cannot outlive the
        // token that proved it, whatever `ttl-seconds` says.
        let expires = match payload.get("exp").and_then(Json::as_i64) {
            Some(exp) => exp.min(now + self.ttl),
            None => now + self.ttl,
        };

        payload.insert("iat".to_owned(), Json::from(now));
        payload.insert("exp".to_owned(), Json::from(expires));
        if let Some(issuer) = &self.issuer {
            payload.insert("iss".to_owned(), Json::from(issuer.as_str()));
        }
        if let Some(audience) = &self.audience {
            payload.insert("aud".to_owned(), Json::from(audience.as_str()));
        }

        let token = encode(&Header::new(Algorithm::HS256), &payload, &self.encoding)
            .map_err(|error| error.to_string())?;

        Ok(format!(
            "{}={token}; Max-Age={}{}",
            self.name,
            (expires - now).max(0),
            self.attributes
        ))
    }
}

/// One cookie's value out of a `Cookie:` header, or `None` if it is not there.
pub fn from_jar<'a>(jar: Option<&'a str>, name: &str) -> Option<&'a str> {
    jar?.split(';')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| key.trim() == name)
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
}

/// A `Cookie:` header with the gateway's own cookies taken out, or `None` when
/// nothing the application sent is left to forward.
///
/// Only the named cookies go: everything else in the jar belongs to the
/// application behind the gateway and dropping it would log the user out of
/// whatever else the page is doing.
pub fn without<'a>(jar: &'a str, names: &HashSet<String>) -> Option<String> {
    let kept: Vec<&'a str> = jar
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            let key = pair.split_once('=').map_or(*pair, |(key, _)| key).trim();
            !names.contains(key)
        })
        .collect();

    (!kept.is_empty()).then(|| kept.join("; "))
}

/// RFC 6265 cookie-name: an HTTP token, so no separators, spaces or controls.
fn is_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_graphic() && !br#"()<>@,;:\"/[]?={}"#.contains(&byte)
        })
}

/// Anything that would end the attribute early or splice a header ends the
/// startup instead.
fn is_attribute_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && byte != b';' && byte != b',')
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

    fn cookie(params: &str) -> Result<Option<SessionCookie>, String> {
        build(
            &yaml_serde::from_str(params).expect("invalid test params"),
            "test-plugin",
        )
    }

    fn built(params: &str) -> SessionCookie {
        cookie(params)
            .expect("the test cookie should build")
            .expect("the test params declare a cookie")
    }

    fn claims(value: Json) -> Map<String, Json> {
        value.as_object().unwrap().to_owned()
    }

    fn minted(cookie: &SessionCookie, claims: &Map<String, Json>) -> String {
        let issued = cookie.issue(
            Credential {
                token: "opaque",
                session: None,
            },
            claims,
        );
        assert_eq!(issued.len(), 1, "a verified identity mints a cookie");
        assert_eq!(issued[0].0, "set-cookie");
        issued[0].1.to_owned()
    }

    /// The `name=value` at the front of a `Set-Cookie`.
    fn token_of(set_cookie: &str) -> &str {
        set_cookie
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
    }

    fn far_future() -> i64 {
        unix_now() + 86_400
    }

    #[test]
    fn a_plugin_without_the_block_mints_nothing() {
        assert!(cookie("other: true").unwrap().is_none());
    }

    #[test]
    fn a_cookie_that_could_not_be_verified_later_is_refused_now() {
        assert!(cookie("session-cookie: {name: s}").is_err());
        assert!(cookie("session-cookie: {secret: ''}").is_err());
        assert!(cookie("session-cookie: {secret: shh}").is_ok());
        // A block that is not a block cannot be read for one.
        assert!(cookie("session-cookie: shh").is_err());
    }

    #[test]
    fn the_defaults_are_the_hardened_ones() {
        let cookie = built("session-cookie: {secret: shh}");
        let set = minted(&cookie, &claims(json!({"sub": "u1"})));

        assert!(set.starts_with(&format!("{DEFAULT_NAME}=")), "{set}");
        assert!(set.contains("; HttpOnly"), "{set}");
        assert!(set.contains("; Secure"), "{set}");
        assert!(set.contains("; SameSite=Lax"), "{set}");
        assert!(set.contains("; Path=/"), "{set}");
        assert!(!set.contains("Domain="), "{set}");
    }

    #[test]
    fn attributes_follow_the_config_when_it_gives_them() {
        let cookie = built(
            "session-cookie: {secret: shh, name: sid, path: /app, domain: example.com, \
             secure: false, http-only: false, same-site: Strict}",
        );
        let set = minted(&cookie, &claims(json!({"sub": "u1"})));

        assert!(set.starts_with("sid="), "{set}");
        assert!(set.contains("; Path=/app"), "{set}");
        assert!(set.contains("; Domain=example.com"), "{set}");
        assert!(set.contains("; SameSite=Strict"), "{set}");
        assert!(!set.contains("HttpOnly"), "{set}");
        assert!(!set.contains("Secure"), "{set}");
    }

    #[test]
    fn a_cookie_a_browser_would_discard_is_refused_at_startup() {
        // `SameSite=None` without `Secure` is dropped outright, so the gateway
        // would hand out sessions that never come back.
        assert!(cookie("session-cookie: {secret: shh, same-site: None, secure: false}").is_err());
        assert!(cookie("session-cookie: {secret: shh, same-site: None}").is_ok());
        assert!(cookie("session-cookie: {secret: shh, same-site: sideways}").is_err());

        // Names and attributes that would splice the header.
        assert!(cookie("session-cookie: {secret: shh, name: 'bad name'}").is_err());
        assert!(cookie("session-cookie: {secret: shh, name: 'a=b'}").is_err());
        assert!(cookie("session-cookie: {secret: shh, path: '/a; Domain=evil.com'}").is_err());
        assert!(cookie("session-cookie: {secret: shh, ttl-seconds: 0}").is_err());
    }

    #[test]
    fn a_minted_cookie_reads_back_as_the_identity_it_was_minted_from() {
        let cookie = built("session-cookie: {secret: shh}");
        let set = minted(&cookie, &claims(json!({"sub": "u1", "scope": "admin"})));

        let read = cookie.claims(token_of(&set)).expect("its own cookie verifies");
        assert_eq!(read["sub"], json!("u1"));
        assert_eq!(read["scope"], json!("admin"));
        assert!(read["exp"].as_i64().unwrap() > unix_now());
        assert!(read.contains_key("iat"));
    }

    #[test]
    fn a_cookie_minted_with_another_secret_is_not_this_ones() {
        let mine = built("session-cookie: {secret: shh}");
        let theirs = built("session-cookie: {secret: different}");

        let set = minted(&theirs, &claims(json!({"sub": "u1"})));
        assert!(mine.claims(token_of(&set)).is_none());
        assert!(mine.claims("not-a-token").is_none());
    }

    #[test]
    fn a_session_never_outlives_the_credential_it_was_minted_from() {
        let cookie = built("session-cookie: {secret: shh, ttl-seconds: 86400}");

        // The provider said this token dies in a minute; the day-long ttl does
        // not get to extend it.
        let soon = unix_now() + 60;
        let set = minted(&cookie, &claims(json!({"sub": "u1", "exp": soon})));
        assert_eq!(cookie.claims(token_of(&set)).unwrap()["exp"], json!(soon));

        // Without a provider expiry the ttl is the whole of it.
        let set = minted(&cookie, &claims(json!({"sub": "u1"})));
        let exp = cookie.claims(token_of(&set)).unwrap()["exp"].as_i64().unwrap();
        assert!(exp > unix_now() + 86_000, "the full ttl should apply");
    }

    #[test]
    fn introspection_bookkeeping_does_not_become_an_identity_claim() {
        let cookie = built("session-cookie: {secret: shh}");
        let set = minted(
            &cookie,
            &claims(json!({"sub": "u1", "active": true, "token_type": "Bearer"})),
        );

        let read = cookie.claims(token_of(&set)).unwrap();
        assert_eq!(read["sub"], json!("u1"));
        // `active: true` was true of a lookup nothing is repeating.
        assert!(!read.contains_key("active"));
        assert!(!read.contains_key("token_type"));
    }

    #[test]
    fn a_configured_issuer_and_audience_are_stamped_and_enforced() {
        let cookie =
            built("session-cookie: {secret: shh, issuer: 'https://gw', audience: gillnet}");
        let set = minted(&cookie, &claims(json!({"sub": "u1"})));

        let read = cookie.claims(token_of(&set)).unwrap();
        assert_eq!(read["iss"], json!("https://gw"));
        assert_eq!(read["aud"], json!("gillnet"));

        // A cookie stamped for someone else does not verify here.
        let other = built("session-cookie: {secret: shh, issuer: 'https://other'}");
        let theirs = minted(&other, &claims(json!({"sub": "u1"})));
        assert!(cookie.claims(token_of(&theirs)).is_none());
    }

    #[test]
    fn a_live_session_is_not_re_stamped_on_every_response() {
        let cookie = built("session-cookie: {secret: shh}");
        let identity = claims(json!({"sub": "u1", "exp": far_future()}));
        let set = minted(&cookie, &identity);
        let carried = token_of(&set);

        // The caller already has this one; there is nothing to send back.
        assert!(cookie
            .issue(
                Credential {
                    token: "opaque",
                    session: Some(carried)
                },
                &identity
            )
            .is_empty());

        // One that no longer verifies is replaced.
        assert_eq!(
            cookie
                .issue(
                    Credential {
                        token: "opaque",
                        session: Some("stale-or-forged")
                    },
                    &identity
                )
                .len(),
            1
        );
    }

    #[test]
    fn a_named_cookie_is_found_among_the_others() {
        let jar = Some("theme=dark; gillnet-session=abc.def.ghi; cart=7");

        assert_eq!(from_jar(jar, DEFAULT_NAME), Some("abc.def.ghi"));
        assert_eq!(from_jar(jar, "theme"), Some("dark"));
        assert_eq!(from_jar(jar, "absent"), None);
        assert_eq!(from_jar(None, DEFAULT_NAME), None);
        // An empty cookie is no credential, exactly as an empty header is none.
        assert_eq!(from_jar(Some("gillnet-session=  "), DEFAULT_NAME), None);
    }

    #[test]
    fn only_the_gateways_own_cookies_are_withheld_from_the_upstream() {
        let names: HashSet<String> = [DEFAULT_NAME.to_owned()].into_iter().collect();

        // The application's cookies are none of the gateway's business.
        assert_eq!(
            without("theme=dark; gillnet-session=abc; cart=7", &names).as_deref(),
            Some("theme=dark; cart=7")
        );
        // A jar holding nothing else is dropped rather than forwarded empty.
        assert_eq!(without("gillnet-session=abc", &names), None);
        assert_eq!(
            without("theme=dark", &names).as_deref(),
            Some("theme=dark")
        );
        assert_eq!(
            without("theme=dark", &HashSet::new()).as_deref(),
            Some("theme=dark")
        );
    }
}
