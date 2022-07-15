use std::collections::HashMap;

use serde_yaml::Value;

use crate::config::*;

pub struct Plugin {
    pub name: String,
    pub ptype: String,
    pub params: HashMap<String, Value>,
}

impl Plugin {
    pub fn from_config(config: &PluginConfig) -> Plugin {
        Plugin {
            name: config.name.to_owned(),
            ptype: config.plugin_id.to_owned(),
            params: config.params.to_owned(),
        }
    }
}

pub struct Service {
    pub name: String,
    pub url: String,
}

impl Service {
    pub fn from_config(config: &ServiceConfig) -> Service {
        Service {
            name: config.name.to_owned(),
            url: config.url.to_owned(),
        }
    }
}

pub struct Route {
    pub name: String,
    pub url: String,
    pub paths: Vec<String>,
    pub strip_path: bool,
    pub plugins: Option<Vec<PluginReference>>,
}

impl Route {
    pub fn from_config(config: &RouteConfig) -> Self {
        Self {
            name: config.name.to_owned(),
            url: config.url.to_owned(),
            paths: config.paths.to_owned(),
            strip_path: config.strip_path,
            plugins: config.plugins.to_owned(),
        }
    }
}
