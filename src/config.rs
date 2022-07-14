use std::collections::HashMap;

use serde::Deserialize;
use serde_yaml::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub plugins: Vec<PluginConfig>,
    pub services: Vec<ServiceConfig>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    pub service: Option<String>,
    pub url: Option<String>,
    pub paths: Vec<String>,

    #[serde(alias = "strip-path")]
    #[serde(alias = "stripPath")]
    #[serde(default)]
    pub strip_path: bool,

    pub plugins: Option<Vec<PluginReference>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginReference {
    pub name: String,
    pub params: Option<HashMap<String, Value>>,
}
