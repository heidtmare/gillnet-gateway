mod config;

use config::{Config, PluginConfig, RouteConfig, ServiceConfig};
use serde_yaml::Value;
use std::{env, fs, iter::Map, collections::HashMap};

fn main() {
    let filename = env::args().nth(1).expect("No config file provided");
    let contents = fs::read_to_string(filename).expect("Could not read config file!");
    let config: Config = serde_yaml::from_str(&contents).expect("Invalid yaml!");

    let plugins: Vec<Plugin> = config
        .plugins
        .iter()
        .map(|cfg| Plugin::from_config(cfg))
        .collect();

    let services: Vec<Service> = config
        .services
        .iter()
        .map(|cfg| Service::from_config(cfg))
        .collect();

    let routes: Vec<Route> = config
        .routes
        .iter()
        .map(|cfg| Route::from_config(cfg))
        .collect();

    println!("{:?}", services.get(0).unwrap().additional);
}

struct Plugin {
    name: String,
    ptype: String,
    pub additional: HashMap<String, Value>,
}
impl Plugin {
    pub fn from_config(config: &PluginConfig) -> Plugin {
        Plugin {
            name: config.name.to_owned(),
            ptype: config.plugin_id.to_owned(),
            additional: config.additional_properties.to_owned(),
        }
    }
}

struct Service {
    pub additional: Value,
}
impl Service {
    pub fn from_config(config: &ServiceConfig) -> Service {
        Service {additional: config.additional_properties.to_owned()}
    }
}

struct Route {}
impl Route {
    pub fn from_config(config: &RouteConfig) -> Route {
        Route {}
    }
}
