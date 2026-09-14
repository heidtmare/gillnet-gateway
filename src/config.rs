use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use yaml_serde::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    #[serde(default)]
    pub listen: ListenConfig,

    #[serde(default)]
    pub registration: RegistrationConfig,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub testing: TestingConfig,

    pub plugins: Option<Vec<PluginConfig>>,
    pub services: Option<Vec<ServiceConfig>>,

    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(alias = "proxy-port")]
    #[serde(alias = "proxyPort")]
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,

    #[serde(alias = "registration-port")]
    #[serde(alias = "registrationPort")]
    #[serde(default = "default_registration_port")]
    pub registration_port: u16,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            proxy_port: default_proxy_port(),
            registration_port: default_registration_port(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationConfig {
    #[serde(alias = "heartbeat-ttl-seconds")]
    #[serde(alias = "heartbeatTtlSeconds")]
    #[serde(default = "default_heartbeat_ttl_seconds")]
    pub heartbeat_ttl_seconds: u64,

    #[serde(alias = "reap-interval-seconds")]
    #[serde(alias = "reapIntervalSeconds")]
    #[serde(default = "default_reap_interval_seconds")]
    pub reap_interval_seconds: u64,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            heartbeat_ttl_seconds: default_heartbeat_ttl_seconds(),
            reap_interval_seconds: default_reap_interval_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(alias = "timeout-seconds")]
    #[serde(alias = "timeoutSeconds")]
    #[serde(default = "default_proxy_timeout_seconds")]
    pub timeout_seconds: u64,

    #[serde(alias = "connect-timeout-seconds")]
    #[serde(alias = "connectTimeoutSeconds")]
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,

    #[serde(alias = "websocket-max-frame-bytes")]
    #[serde(alias = "websocketMaxFrameBytes")]
    #[serde(default = "default_websocket_max_frame_bytes")]
    pub websocket_max_frame_bytes: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_proxy_timeout_seconds(),
            connect_timeout_seconds: default_connect_timeout_seconds(),
            websocket_max_frame_bytes: default_websocket_max_frame_bytes(),
        }
    }
}

/// Off unless a config file says otherwise, because the only thing standing
/// between these endpoints and the public proxy listener is this flag.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestingConfig {
    /// Mounts /testing/userinfo on the proxy port and lets the claim sets
    /// posted there stand in for the authorization provider. Test only.
    #[serde(alias = "userinfo-overrides")]
    #[serde(alias = "userinfoOverrides")]
    #[serde(default)]
    pub userinfo_overrides: bool,
}

fn default_websocket_max_frame_bytes() -> usize {
    64 * 1024
}

fn default_proxy_timeout_seconds() -> u64 {
    30
}

fn default_connect_timeout_seconds() -> u64 {
    5
}

fn default_host() -> String {
    "0.0.0.0".to_owned()
}

fn default_proxy_port() -> u16 {
    8080
}

fn default_registration_port() -> u16 {
    8081
}

fn default_heartbeat_ttl_seconds() -> u64 {
    30
}

fn default_reap_interval_seconds() -> u64 {
    10
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    pub name: String,

    #[serde(alias = "type")]
    pub plugin_id: String,

    #[serde(default)]
    pub params: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    pub url: String,
    pub paths: Vec<String>,

    #[serde(alias = "match-type")]
    #[serde(alias = "matchType")]
    #[serde(default)]
    pub match_type: MatchType,

    #[serde(alias = "strip-path")]
    #[serde(alias = "stripPath")]
    #[serde(default)]
    pub strip_path: bool,

    /// Whether the credential the guards authenticated with is relayed to the
    /// upstream. Off by default: a backend behind the gateway has no need for
    /// the caller's token, and forwarding one hands it a credential it can
    /// replay elsewhere.
    #[serde(alias = "forward-token")]
    #[serde(alias = "forwardToken")]
    #[serde(default)]
    pub forward_token: bool,

    pub plugins: Option<Vec<PluginReference>>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub enum MatchType {
    EXACT,
    #[default]
    PREFIX,
    REGEX,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginReference {
    pub name: String,
    pub params: Option<HashMap<String, Value>>,
}
