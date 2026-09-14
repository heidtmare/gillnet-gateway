use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::auth::{AuthPolicy, RouteGuard};
use crate::config::{GatewayConfig, MatchType, RouteConfig};

pub struct Registry {
    static_routes: Vec<CompiledRoute>,
    static_services: HashMap<String, String>,
    policies: HashMap<String, Arc<AuthPolicy>>,
    services: HashMap<String, RegisteredService>,
    ttl: Duration,
    userinfo_overrides: bool,
}

#[derive(Default)]
struct RegisteredService {
    routes: Vec<CompiledRoute>,
    instances: HashMap<String, Instance>,
    cursor: AtomicUsize,
}

struct Instance {
    url: String,
    last_heartbeat: Instant,
}

struct CompiledRoute {
    name: String,
    target: Target,
    strip_path: bool,
    match_type: MatchType,
    paths: Vec<String>,
    patterns: Vec<Pattern>,
    guards: Vec<RouteGuard>,
}

enum Target {
    Url(String),
    Service(String),
}

enum Pattern {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

struct PathMatch {
    rank: u8,
    matched_len: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    pub service: String,
    pub instance_id: String,
    pub url: String,

    #[serde(default)]
    pub routes: Vec<RouteSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteSpec {
    pub paths: Vec<String>,

    #[serde(default)]
    pub match_type: MatchType,

    #[serde(default)]
    pub strip_path: bool,

    #[serde(default)]
    pub plugins: Vec<PluginRequirement>,
}

/// What a self-registering service may say about auth: which gateway-defined
/// policy it needs, never the credentials themselves.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRequirement {
    pub name: String,

    #[serde(default)]
    pub roles: Vec<String>,

    #[serde(default)]
    pub insert_headers: HashMap<String, String>,
}

pub enum RegistrationError {
    Invalid(String),
    Conflict(String),
}

pub enum Resolution {
    Resolved(Resolved),
    NoInstances { route: String, service: String },
    NotFound,
}

pub struct Resolved {
    pub route: String,
    pub source: &'static str,
    pub service: Option<String>,
    pub instance: Option<String>,
    pub target_url: String,
    pub guards: Vec<RouteGuard>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceView {
    pub service: String,
    pub instances: Vec<InstanceView>,
    pub routes: Vec<RouteView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceView {
    pub instance_id: String,
    pub url: String,
    pub seconds_since_heartbeat: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteView {
    pub paths: Vec<String>,
    pub match_type: MatchType,
    pub strip_path: bool,
    pub plugins: Vec<String>,
}

/// Where a registration came from: the declarative config file, or a service
/// that registered itself at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Source {
    Static,
    Dynamic,
}

/// Narrows what `describe` returns. An empty list means "no filter on this
/// field"; filters combine with AND.
#[derive(Debug, Default)]
pub struct DescribeFilter {
    pub services: Vec<String>,
    pub routes: Vec<String>,
    pub plugins: Vec<String>,
    pub source: Option<Source>,
    pub path: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeView {
    pub summary: SummaryView,
    pub plugins: Vec<PluginView>,
    pub services: Vec<DescribedService>,
    pub routes: Vec<DescribedRoute>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryView {
    pub heartbeat_ttl_seconds: u64,

    /// Surfaced so an operator can confirm at a glance that a production
    /// gateway is not accepting test claim overrides.
    pub testing_userinfo_overrides: bool,

    pub services: usize,
    pub instances: usize,
    pub routes: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginView {
    pub name: String,
    pub r#type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribedService {
    pub service: String,
    pub source: Source,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    pub instances: Vec<InstanceView>,
    pub routes: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribedRoute {
    pub name: String,
    pub source: Source,
    pub target: TargetView,
    pub paths: Vec<String>,
    pub match_type: MatchType,
    pub strip_path: bool,
    pub plugins: Vec<GuardView>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TargetView {
    Url {
        url: String,
    },
    Service {
        service: String,
        /// Where the service name resolves today: the static `services:` block,
        /// the self-registration registry, or nowhere (requests would 503).
        resolution: &'static str,
        instances: usize,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardView {
    pub name: String,
    pub r#type: &'static str,
    pub roles: Vec<String>,
    pub insert_headers: HashMap<String, String>,
}

impl Registry {
    pub fn from_config(config: &GatewayConfig) -> Self {
        let mut policies: HashMap<String, Arc<AuthPolicy>> = HashMap::new();
        for plugin in config.plugins.iter().flatten() {
            let policy = AuthPolicy::from_config(plugin)
                .unwrap_or_else(|e| panic!("Invalid plugin '{}': {e}", plugin.name));
            if policies
                .insert(plugin.name.to_owned(), Arc::new(policy))
                .is_some()
            {
                panic!(
                    "A plugin named '{}' is declared twice in the declarative configuration!",
                    plugin.name
                );
            }
        }

        let mut static_services = HashMap::new();
        for service in config.services.iter().flatten() {
            if static_services
                .insert(service.name.to_owned(), service.url.to_owned())
                .is_some()
            {
                panic!(
                    "A service named '{}' is declared twice in the declarative configuration!",
                    service.name
                );
            }
        }

        let mut seen = Vec::with_capacity(config.routes.len());
        let mut static_routes = Vec::with_capacity(config.routes.len());
        for route in &config.routes {
            if seen.contains(&&route.name) {
                panic!(
                    "A route named '{}' is declared twice in the declarative configuration!",
                    route.name
                );
            }
            seen.push(&route.name);
            static_routes.push(
                CompiledRoute::from_config(route, &policies)
                    .unwrap_or_else(|e| panic!("Invalid route '{}': {e}", route.name)),
            );
        }

        Self {
            static_routes,
            static_services,
            policies,
            services: HashMap::new(),
            ttl: Duration::from_secs(config.registration.heartbeat_ttl_seconds),
            userinfo_overrides: config.testing.userinfo_overrides,
        }
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl.as_secs()
    }

    pub fn register(&mut self, request: RegistrationRequest) -> Result<(), RegistrationError> {
        if request.service.trim().is_empty() {
            return Err(RegistrationError::Invalid("service must not be empty".to_owned()));
        }
        if request.instance_id.trim().is_empty() {
            return Err(RegistrationError::Invalid(
                "instanceId must not be empty".to_owned(),
            ));
        }
        if !request.url.starts_with("http://") && !request.url.starts_with("https://") {
            return Err(RegistrationError::Invalid(
                "url must start with http:// or https://".to_owned(),
            ));
        }
        if self.static_services.contains_key(&request.service) {
            return Err(RegistrationError::Conflict(format!(
                "service '{}' is statically defined in the gateway config and cannot self-register",
                request.service
            )));
        }

        let routes = request
            .routes
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                CompiledRoute::from_spec(&request.service, index, spec, &self.policies)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(RegistrationError::Invalid)?;

        let entry = self.services.entry(request.service).or_default();
        if !routes.is_empty() {
            entry.routes = routes;
        }
        entry.instances.insert(
            request.instance_id,
            Instance {
                url: request.url,
                last_heartbeat: Instant::now(),
            },
        );
        Ok(())
    }

    pub fn heartbeat(&mut self, service: &str, instance_id: &str) -> bool {
        match self
            .services
            .get_mut(service)
            .and_then(|entry| entry.instances.get_mut(instance_id))
        {
            Some(instance) => {
                instance.last_heartbeat = Instant::now();
                true
            }
            None => false,
        }
    }

    pub fn deregister(&mut self, service: &str, instance_id: &str) -> bool {
        let Some(entry) = self.services.get_mut(service) else {
            return false;
        };
        let removed = entry.instances.remove(instance_id).is_some();
        if entry.instances.is_empty() {
            self.services.remove(service);
        }
        removed
    }

    pub fn reap(&mut self) -> Vec<(String, String)> {
        let now = Instant::now();
        let ttl = self.ttl;
        let mut expired = Vec::new();

        for (service, entry) in self.services.iter_mut() {
            entry.instances.retain(|instance_id, instance| {
                let alive = now.saturating_duration_since(instance.last_heartbeat) <= ttl;
                if !alive {
                    expired.push((service.to_owned(), instance_id.to_owned()));
                }
                alive
            });
        }
        self.services.retain(|_, entry| !entry.instances.is_empty());

        expired
    }

    pub fn snapshot(&self) -> Vec<ServiceView> {
        let now = Instant::now();
        let mut views: Vec<ServiceView> = self
            .services
            .iter()
            .map(|(service, entry)| ServiceView {
                service: service.to_owned(),
                instances: entry.instance_views(now),
                routes: entry
                    .routes
                    .iter()
                    .map(|route| RouteView {
                        paths: route.paths.to_owned(),
                        match_type: route.match_type,
                        strip_path: route.strip_path,
                        plugins: route.guards.iter().map(|g| g.name().to_owned()).collect(),
                    })
                    .collect(),
            })
            .collect();
        views.sort_by(|a, b| a.service.cmp(&b.service));
        views
    }

    /// Full picture of what the gateway will route, for operators and tooling.
    /// Reports configuration only -- never plugin credentials.
    pub fn describe(&self, filter: &DescribeFilter) -> DescribeView {
        let now = Instant::now();

        let mut routes = Vec::new();
        let mut targeted: Vec<&str> = Vec::new();

        let candidates = self
            .static_routes
            .iter()
            .map(|route| (route, Source::Static))
            .chain(
                self.services
                    .values()
                    .flat_map(|entry| entry.routes.iter())
                    .map(|route| (route, Source::Dynamic)),
            );

        for (route, source) in candidates {
            if !self.route_matches(route, source, filter) {
                continue;
            }
            if let Target::Service(name) = &route.target {
                targeted.push(name);
            }
            routes.push(self.describe_route(route, source));
        }
        routes.sort_by(|a, b| a.name.cmp(&b.name));

        // A route-shaped filter also narrows the services: only those the
        // surviving routes actually point at are worth reporting.
        let narrowed =
            !filter.routes.is_empty() || !filter.plugins.is_empty() || filter.path.is_some();

        let mut services = Vec::new();

        for (service, url) in &self.static_services {
            if !Self::service_matches(service, Source::Static, filter, narrowed, &targeted) {
                continue;
            }
            services.push(DescribedService {
                service: service.to_owned(),
                source: Source::Static,
                url: Some(url.to_owned()),
                instances: Vec::new(),
                routes: route_names(&routes, service),
            });
        }

        for (service, entry) in &self.services {
            if !Self::service_matches(service, Source::Dynamic, filter, narrowed, &targeted) {
                continue;
            }
            services.push(DescribedService {
                service: service.to_owned(),
                source: Source::Dynamic,
                url: None,
                instances: entry.instance_views(now),
                routes: route_names(&routes, service),
            });
        }
        services.sort_by(|a, b| a.service.cmp(&b.service));

        let mut plugins: Vec<PluginView> = self
            .policies
            .iter()
            .filter(|(name, _)| {
                filter.plugins.is_empty() || filter.plugins.iter().any(|p| p == *name)
            })
            .map(|(name, policy)| PluginView {
                name: name.to_owned(),
                r#type: policy.kind(),
            })
            .collect();
        plugins.sort_by(|a, b| a.name.cmp(&b.name));

        DescribeView {
            summary: SummaryView {
                heartbeat_ttl_seconds: self.ttl.as_secs(),
                testing_userinfo_overrides: self.userinfo_overrides,
                services: services.len(),
                instances: services.iter().map(|s| s.instances.len()).sum(),
                routes: routes.len(),
            },
            plugins,
            services,
            routes,
        }
    }

    fn route_matches(
        &self,
        route: &CompiledRoute,
        source: Source,
        filter: &DescribeFilter,
    ) -> bool {
        if filter.source.is_some_and(|wanted| wanted != source) {
            return false;
        }
        if !filter.routes.is_empty() && !filter.routes.contains(&route.name) {
            return false;
        }
        if !filter.services.is_empty() {
            match &route.target {
                Target::Service(name) => {
                    if !filter.services.iter().any(|service| service == name) {
                        return false;
                    }
                }
                // A route straight to a URL belongs to no service.
                Target::Url(_) => return false,
            }
        }
        if !filter.plugins.is_empty()
            && !route
                .guards
                .iter()
                .any(|guard| filter.plugins.iter().any(|name| name == guard.name()))
        {
            return false;
        }
        if let Some(path) = &filter.path {
            if route.match_path(path).is_none() {
                return false;
            }
        }
        true
    }

    fn service_matches(
        service: &str,
        source: Source,
        filter: &DescribeFilter,
        narrowed: bool,
        targeted: &[&str],
    ) -> bool {
        if filter.source.is_some_and(|wanted| wanted != source) {
            return false;
        }
        if !filter.services.is_empty() && !filter.services.iter().any(|name| name == service) {
            return false;
        }
        if narrowed && !targeted.contains(&service) {
            return false;
        }
        true
    }

    fn describe_route(&self, route: &CompiledRoute, source: Source) -> DescribedRoute {
        DescribedRoute {
            name: route.name.to_owned(),
            source,
            target: match &route.target {
                Target::Url(url) => TargetView::Url {
                    url: url.to_owned(),
                },
                Target::Service(name) => {
                    let registered = self.services.get(name);
                    TargetView::Service {
                        service: name.to_owned(),
                        resolution: if self.static_services.contains_key(name) {
                            "static"
                        } else if registered.is_some() {
                            "registry"
                        } else {
                            "unresolved"
                        },
                        instances: registered.map_or(0, |entry| entry.instances.len()),
                    }
                }
            },
            paths: route.paths.to_owned(),
            match_type: route.match_type,
            strip_path: route.strip_path,
            plugins: route
                .guards
                .iter()
                .map(|guard| GuardView {
                    name: guard.name().to_owned(),
                    r#type: guard.policy_kind(),
                    roles: guard.required_roles().to_vec(),
                    insert_headers: guard
                        .insert_headers()
                        .iter()
                        .map(|(header, template)| (header.to_owned(), template.to_owned()))
                        .collect(),
                })
                .collect(),
        }
    }

    pub fn resolve(&self, path: &str) -> Resolution {
        if let Some((route, matched)) = best_match(self.static_routes.iter(), path) {
            return self.build(route, matched, path, "static");
        }

        let dynamic = self.services.values().flat_map(|entry| entry.routes.iter());
        match best_match(dynamic, path) {
            Some((route, matched)) => self.build(route, matched, path, "dynamic"),
            None => Resolution::NotFound,
        }
    }

    fn build(
        &self,
        route: &CompiledRoute,
        matched: PathMatch,
        path: &str,
        source: &'static str,
    ) -> Resolution {
        let upstream_path = if route.strip_path {
            strip_prefix(path, matched.matched_len)
        } else {
            path.to_owned()
        };

        let (service, instance, base_url) = match &route.target {
            Target::Url(url) => (None, None, url.to_owned()),
            Target::Service(name) => match self.static_services.get(name) {
                Some(url) => (Some(name.to_owned()), None, url.to_owned()),
                None => match self.pick_instance(name) {
                    Some((instance_id, url)) => (Some(name.to_owned()), Some(instance_id), url),
                    None => {
                        return Resolution::NoInstances {
                            route: route.name.to_owned(),
                            service: name.to_owned(),
                        }
                    }
                },
            },
        };

        Resolution::Resolved(Resolved {
            route: route.name.to_owned(),
            source,
            service,
            instance,
            target_url: format!("{}{}", base_url.trim_end_matches('/'), upstream_path),
            guards: route.guards.to_owned(),
        })
    }

    fn pick_instance(&self, service: &str) -> Option<(String, String)> {
        let entry = self.services.get(service)?;
        let mut instance_ids: Vec<&String> = entry.instances.keys().collect();
        instance_ids.sort();

        let index = entry.cursor.fetch_add(1, Ordering::Relaxed) % instance_ids.len().max(1);
        let instance_id = instance_ids.get(index)?;

        Some((
            (*instance_id).to_owned(),
            entry.instances[*instance_id].url.to_owned(),
        ))
    }
}

impl RegisteredService {
    fn instance_views(&self, now: Instant) -> Vec<InstanceView> {
        let mut views: Vec<InstanceView> = self
            .instances
            .iter()
            .map(|(instance_id, instance)| InstanceView {
                instance_id: instance_id.to_owned(),
                url: instance.url.to_owned(),
                seconds_since_heartbeat: now
                    .saturating_duration_since(instance.last_heartbeat)
                    .as_secs(),
            })
            .collect();
        views.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
        views
    }
}

impl CompiledRoute {
    fn from_config(
        config: &RouteConfig,
        policies: &HashMap<String, Arc<AuthPolicy>>,
    ) -> Result<Self, String> {
        let guards = config
            .plugins
            .iter()
            .flatten()
            .map(|reference| {
                let policy = lookup(policies, &reference.name)?;
                RouteGuard::from_reference(reference, policy)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name: config.name.to_owned(),
            target: Target::parse(&config.url),
            strip_path: config.strip_path,
            match_type: config.match_type,
            paths: config.paths.to_owned(),
            patterns: compile_patterns(&config.paths, config.match_type)?,
            guards,
        })
    }

    fn from_spec(
        service: &str,
        index: usize,
        spec: &RouteSpec,
        policies: &HashMap<String, Arc<AuthPolicy>>,
    ) -> Result<Self, String> {
        let guards = spec
            .plugins
            .iter()
            .map(|requirement| {
                let policy = lookup(policies, &requirement.name)?;
                RouteGuard::build(
                    &requirement.name,
                    policy,
                    requirement.roles.to_owned(),
                    requirement
                        .insert_headers
                        .iter()
                        .map(|(header, template)| (header.to_owned(), template.to_owned()))
                        .collect(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            name: format!("{service}#{index}"),
            target: Target::Service(service.to_owned()),
            strip_path: spec.strip_path,
            match_type: spec.match_type,
            paths: spec.paths.to_owned(),
            patterns: compile_patterns(&spec.paths, spec.match_type)?,
            guards,
        })
    }

    fn match_path(&self, path: &str) -> Option<PathMatch> {
        self.patterns
            .iter()
            .filter_map(|pattern| pattern.match_path(path))
            .max_by_key(|matched| (matched.rank, matched.matched_len))
    }
}

impl Target {
    fn parse(url: &str) -> Self {
        if url.starts_with("http://") || url.starts_with("https://") {
            Target::Url(url.to_owned())
        } else {
            Target::Service(url.to_owned())
        }
    }
}

impl Pattern {
    fn match_path(&self, path: &str) -> Option<PathMatch> {
        match self {
            Pattern::Exact(exact) => (path == exact).then_some(PathMatch {
                rank: 2,
                matched_len: exact.len(),
            }),
            Pattern::Prefix(prefix) => {
                let matches = prefix.is_empty()
                    || path == prefix
                    || (path.starts_with(prefix.as_str())
                        && path.as_bytes().get(prefix.len()) == Some(&b'/'));

                matches.then_some(PathMatch {
                    rank: 1,
                    matched_len: prefix.len(),
                })
            }
            Pattern::Regex(regex) => {
                let found = regex.find(path)?;
                (found.start() == 0).then_some(PathMatch {
                    rank: 0,
                    matched_len: found.end(),
                })
            }
        }
    }
}

/// An unknown plugin name is rejected rather than ignored: a typo must not
/// silently leave a route unauthenticated.
fn lookup(
    policies: &HashMap<String, Arc<AuthPolicy>>,
    name: &str,
) -> Result<Arc<AuthPolicy>, String> {
    policies
        .get(name)
        .cloned()
        .ok_or_else(|| format!("unknown plugin '{name}' (not defined in the gateway config)"))
}

/// Names of the already-filtered routes that point at this service, so a
/// service entry links back to what reaches it.
fn route_names(routes: &[DescribedRoute], service: &str) -> Vec<String> {
    routes
        .iter()
        .filter(|route| {
            matches!(&route.target, TargetView::Service { service: name, .. } if name == service)
        })
        .map(|route| route.name.to_owned())
        .collect()
}

fn compile_patterns(paths: &[String], match_type: MatchType) -> Result<Vec<Pattern>, String> {
    paths
        .iter()
        .map(|path| match match_type {
            MatchType::EXACT => Ok(Pattern::Exact(path.to_owned())),
            MatchType::PREFIX => Ok(Pattern::Prefix(path.trim_end_matches('/').to_owned())),
            MatchType::REGEX => Regex::new(path)
                .map(Pattern::Regex)
                .map_err(|e| e.to_string()),
        })
        .collect()
}

fn best_match<'a>(
    routes: impl Iterator<Item = &'a CompiledRoute>,
    path: &str,
) -> Option<(&'a CompiledRoute, PathMatch)> {
    routes
        .filter_map(|route| route.match_path(path).map(|matched| (route, matched)))
        .max_by_key(|(_, matched)| (matched.rank, matched.matched_len))
}

fn strip_prefix(path: &str, matched_len: usize) -> String {
    let remainder = &path[matched_len..];
    if remainder.is_empty() {
        "/".to_owned()
    } else if remainder.starts_with('/') {
        remainder.to_owned()
    } else {
        format!("/{remainder}")
    }
}
