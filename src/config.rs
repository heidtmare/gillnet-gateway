use std::collections::HashMap;

use serde::Deserialize;
use serde_yaml::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub plugins: Option<Vec<PluginConfig>>,
    pub services: Option<Vec<ServiceConfig>>,
    pub routes: Vec<RouteConfig>,
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

    pub plugins: Option<Vec<PluginReference>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
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
