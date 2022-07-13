use std::{iter::Map, collections::HashMap};

use serde::Deserialize;
use serde_yaml::Value;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub plugins: Vec<PluginConfig>,
    pub services: Vec<ServiceConfig>,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize)]
pub struct PluginConfig {
    pub name: String,

    #[serde(alias = "type")]
    pub plugin_id: String,

    #[serde(flatten)]
    pub additional_properties: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub url: String,

    #[serde(flatten)]
    pub additional_properties: Value,
}

#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    pub name: String,

    #[serde(flatten)]
    pub additional_properties: Value,
}
