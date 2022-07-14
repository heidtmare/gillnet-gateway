mod components;
mod config;

use std::{collections::HashMap, env, fs};

use config::{PluginConfig, ServiceConfig, RouteConfig};

use crate::{
    components::{Plugin, Route, Service},
    config::Config,
};

fn main() {
    let filename = env::args().nth(1).expect("No config file provided");
    let contents = fs::read_to_string(filename).expect("Could not read config file!");
    let config: Config = serde_yaml::from_str(&contents).expect("Invalid yaml!");

    let plugins = init_plugins(config.plugins);

    let services = init_services(config.services);

    let routes = init_routes(config.routes);
}

fn init_routes(route_configs: Vec<RouteConfig>) -> HashMap<String, Route>{
    let mut routes: HashMap<String, Route> = HashMap::with_capacity(route_configs.len());
    for route_config in route_configs {
        if routes.contains_key(&route_config.name) {
            panic!(
                "A route named '{}' is declaried twice in the declarative configuration!",
                &route_config.name
            );
        }

        let route = Route::from_config(&route_config);
        routes.insert(route_config.name, route);
    }
    routes
}

fn init_services(service_configs: Vec<ServiceConfig>) -> HashMap<String, Service> {
    let mut services: HashMap<String, Service> = HashMap::with_capacity(service_configs.len());
    for service_config in service_configs {
        if services.contains_key(&service_config.name) {
            panic!(
                "A service named '{}' is declaried twice in the declarative configuration!",
                &service_config.name
            );
        }

        let service = Service::from_config(&service_config);
        services.insert(service_config.name, service);
    }
    services
}

fn init_plugins(plugin_configs: Vec<PluginConfig>) -> HashMap<String, Plugin> {
    let mut plugins: HashMap<String, Plugin> = HashMap::with_capacity(plugin_configs.len());
    for plugin_config in plugin_configs {
        if plugins.contains_key(&plugin_config.name) {
            panic!(
                "A plugin named '{}' is declaried twice in the declarative configuration!",
                &plugin_config.name
            );
        }

        let plugin = Plugin::from_config(&plugin_config);
        plugins.insert(plugin_config.name, plugin);
    }
    plugins
}
