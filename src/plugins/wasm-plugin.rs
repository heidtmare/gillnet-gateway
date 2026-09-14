//! `wasm-plugin`: a WebAssembly module filters the request.
//!
//! The one plugin type that is not an [`AuthPlugin`](super::AuthPlugin). It
//! runs after a route's guards have passed, so a module never sees a request
//! the gateway was going to refuse, and it answers with header edits or a
//! response of its own rather than with claims.
//!
//! An entry in the `plugins:` block compiles one module once at
//! startup and gives it base settings. Routes reference it by name and may
//! layer their own settings over that base; the merge happens at config time,
//! so a request only pays for instantiation and the call itself.
//!
//! Each call gets a fresh `Store` and instance. That costs a little more than
//! pooling would, but it means a module cannot carry state -- or a leaked
//! credential -- from one request into the next, which is the property worth
//! paying for in a gateway. Guest execution is bounded by fuel and its memory
//! by a limiter, so a module that loops forever or allocates without bound
//! trips its budget and fails the request instead of taking the worker down.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use actix_web::http::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::{json, Map, Value as Json};
use wasmtime::{Caller, Config, Engine, InstancePre, Linker, Module, Store, StoreLimits,
               StoreLimitsBuilder};
use yaml_serde::Value as Yaml;

use crate::config::{PluginConfig, PluginReference};
use crate::plugins;

/// The `type:` a gateway config declares one of these with.
pub const KIND: &str = "wasm-plugin";

/// Exports a module must provide, and the one it may omit.
const EXPORT_ALLOC: &str = "gillnet_alloc";
const EXPORT_ON_REQUEST: &str = "gillnet_on_request";
const EXPORT_ON_RESPONSE: &str = "gillnet_on_response";

/// Enough for a few milliseconds of guest work on a small module. A filter
/// that needs more than this is doing something a gateway hop should not.
const DEFAULT_FUEL: u64 = 10_000_000;
const DEFAULT_MEMORY_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Refuses a guest that returns an implausible amount of JSON before we try to
/// parse it, so a runaway module cannot turn into a host-side allocation.
const MAX_VERDICT_BYTES: usize = 1024 * 1024;

/// One compiled module plus the settings and budgets from its `plugins:` entry.
/// Shared by every route that references it.
pub struct WasmPlugin {
    name: String,
    module_path: PathBuf,
    instance_pre: InstancePre<HostState>,
    engine: Engine,
    settings: Json,
    fuel: u64,
    memory_max_bytes: usize,
    fail_open: bool,
    has_response_phase: bool,
}

/// A route's binding to a plugin: the shared module, plus the settings that
/// route sees -- the plugin's base settings with the route's layered over.
#[derive(Clone)]
pub struct WasmFilter {
    plugin: Arc<WasmPlugin>,
    settings: Json,
}

/// Per-`Store` host state. `StoreLimits` is what caps guest memory growth.
pub struct HostState {
    plugin: String,
    limits: StoreLimits,
}

/// What a guest decided about a request.
pub enum FilterOutcome {
    /// Forward upstream, applying these header changes first.
    Continue(HeaderEdits),
    /// Answer the client here; the upstream is never contacted.
    Stop(Box<StopResponse>),
    /// The module itself failed and the plugin is not configured to fail open.
    Failed(String),
}

#[derive(Default)]
pub struct HeaderEdits {
    /// Headers the gateway sets from the guest's verdict. A client-supplied
    /// copy of any of these is dropped, exactly as for auth-injected headers.
    pub set: Vec<(String, String)>,
    pub remove: Vec<String>,
}

pub struct StopResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// The JSON a guest returns. Unknown fields are tolerated so a module written
/// against a later ABI still works against this one.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Verdict {
    #[serde(default)]
    action: Action,

    #[serde(default)]
    set_headers: HashMap<String, String>,

    #[serde(default)]
    remove_headers: Vec<String>,

    status: Option<u16>,

    #[serde(default)]
    headers: HashMap<String, String>,

    #[serde(default)]
    body: String,
}

#[derive(Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Action {
    #[default]
    Continue,
    Stop,
}

/// Holds the one `Engine` every module is compiled against. Built lazily, so a
/// gateway with no wasm plugins never pays for a compiler.
pub struct WasmRuntime {
    engine: Engine,
}

impl WasmRuntime {
    pub fn new() -> Result<Self, String> {
        let mut config = Config::new();
        // Fuel is what makes a runaway guest terminate rather than hang a worker.
        config.consume_fuel(true);
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);

        Engine::new(&config)
            .map(|engine| Self { engine })
            .map_err(|error| format!("could not start the WebAssembly engine: {error}"))
    }

    /// Compiles the module and validates its ABI now, so a missing export is a
    /// startup failure rather than a 500 on the first request that hits it.
    pub fn load(&self, config: &PluginConfig) -> Result<WasmPlugin, String> {
        let path = match config.params.get("path") {
            Some(Yaml::String(path)) => PathBuf::from(plugins::expand_env(path)?),
            Some(_) => return Err(format!("{KIND} 'path' must be a string")),
            None => return Err(format!("{KIND} requires 'path' to a .wasm module")),
        };

        let module = Module::from_file(&self.engine, &path).map_err(|error| {
            format!("could not load module '{}': {error}", path.display())
        })?;

        let exports: Vec<&str> = module.exports().map(|export| export.name()).collect();
        for required in [EXPORT_ALLOC, EXPORT_ON_REQUEST, "memory"] {
            if !exports.contains(&required) {
                return Err(format!(
                    "module '{}' does not export '{required}' (see the wasm-plugin ABI)",
                    path.display()
                ));
            }
        }
        let has_response_phase = exports.contains(&EXPORT_ON_RESPONSE);

        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        host_functions(&mut linker)?;
        let instance_pre = linker
            .instantiate_pre(&module)
            .map_err(|error| format!("module '{}' could not be linked: {error}", path.display()))?;

        Ok(WasmPlugin {
            name: config.name.to_owned(),
            module_path: path,
            instance_pre,
            engine: self.engine.clone(),
            settings: settings_of(&config.params, KIND)?,
            fuel: plugins::number(&config.params, "fuel", DEFAULT_FUEL)?,
            memory_max_bytes: plugins::number(
                &config.params,
                "memory-max-bytes",
                DEFAULT_MEMORY_MAX_BYTES as u64,
            )? as usize,
            fail_open: plugins::flag(&config.params, "fail-open")?,
            has_response_phase,
        })
    }
}

/// Everything the host offers a guest. Deliberately almost nothing: a filter
/// gets the request it was handed and a way to say something to the log, and
/// no clock, filesystem, or network.
fn host_functions(linker: &mut Linker<HostState>) -> Result<(), String> {
    linker
        .func_wrap(
            "gillnet",
            "log",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                let Some(message) = read_memory(&mut caller, ptr, len) else {
                    return;
                };
                eprintln!("wasm plugin '{}': {message}", caller.data().plugin);
            },
        )
        .map_err(|error| format!("could not define the host 'gillnet.log' function: {error}"))?;

    Ok(())
}

impl WasmPlugin {
    pub fn kind(&self) -> &'static str {
        KIND
    }

    pub fn module_path(&self) -> &std::path::Path {
        &self.module_path
    }

    pub fn settings(&self) -> &Json {
        &self.settings
    }
}

impl WasmFilter {
    /// Binds a route to a plugin, merging the route's `params.settings` over
    /// the plugin's base settings once, here, rather than on every request.
    pub fn from_reference(
        plugin: Arc<WasmPlugin>,
        reference: &PluginReference,
    ) -> Result<Self, String> {
        let params = reference.params.clone().unwrap_or_default();

        if params.contains_key("roles") || params.contains_key("insert-headers") {
            return Err(format!(
                "plugin '{}' is a {KIND}; 'roles' and 'insert-headers' belong to auth \
                 plugins, put per-route values under 'settings'",
                reference.name
            ));
        }

        Self::build(plugin, settings_of(&params, "a wasm-plugin route reference")?)
    }

    /// The self-registration path, where a service supplies settings directly.
    pub fn build(plugin: Arc<WasmPlugin>, overrides: Json) -> Result<Self, String> {
        let settings = merge(plugin.settings.clone(), overrides);
        Ok(Self { plugin, settings })
    }

    pub fn name(&self) -> &str {
        &self.plugin.name
    }

    pub fn kind(&self) -> &'static str {
        self.plugin.kind()
    }

    pub fn settings(&self) -> &Json {
        &self.settings
    }

    pub fn has_response_phase(&self) -> bool {
        self.plugin.has_response_phase
    }
}

/// Runs each filter in declared order. The first one to stop wins: later
/// filters do not run, because a request that has already been answered is no
/// longer theirs to inspect. Header edits from the filters that did run
/// accumulate.
pub fn on_request(
    filters: &[WasmFilter],
    route: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &actix_web::http::header::HeaderMap,
) -> FilterOutcome {
    if filters.is_empty() {
        return FilterOutcome::Continue(HeaderEdits::default());
    }

    let header_json = collect_headers(headers);
    let mut edits = HeaderEdits::default();

    for filter in filters {
        // Each filter sees the edits made before it, so a chain composes the
        // way an operator reading the config top to bottom would expect.
        let mut visible = header_json.clone();
        apply_to_json(&mut visible, &edits);

        let input = json!({
            "phase": "request",
            "route": route,
            "method": method,
            "path": path,
            "query": query,
            "headers": visible,
            "settings": filter.settings,
        });

        match call(filter, EXPORT_ON_REQUEST, &input) {
            Ok(verdict) => match into_outcome(filter, verdict) {
                FilterOutcome::Continue(mut theirs) => {
                    edits.set.append(&mut theirs.set);
                    edits.remove.append(&mut theirs.remove);
                }
                stopped => return stopped,
            },
            Err(error) => {
                if let Some(failure) = fail(filter, "request", &error) {
                    return failure;
                }
            }
        }
    }

    FilterOutcome::Continue(edits)
}

/// The response phase can only edit headers. The body is a stream that is
/// already on its way to the client by the time this runs, so there is nothing
/// left to stop.
pub fn on_response(
    filters: &[WasmFilter],
    route: &str,
    status: u16,
    headers: &[(HeaderName, HeaderValue)],
) -> HeaderEdits {
    let mut edits = HeaderEdits::default();

    let header_json: Map<String, Json> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), Json::String(value.to_owned())))
        })
        .collect();

    for filter in filters.iter().filter(|f| f.has_response_phase()) {
        let mut visible = header_json.clone();
        apply_to_json(&mut visible, &edits);

        let input = json!({
            "phase": "response",
            "route": route,
            "status": status,
            "headers": visible,
            "settings": filter.settings,
        });

        match call(filter, EXPORT_ON_RESPONSE, &input) {
            Ok(verdict) => {
                let (mut set, mut remove) = header_edits(filter, &verdict);
                edits.set.append(&mut set);
                edits.remove.append(&mut remove);
            }
            // A failing response filter cannot refuse a response that is
            // already being relayed, so it is logged and the headers stand.
            Err(error) => {
                eprintln!(
                    "wasm plugin '{}' failed in the response phase for route '{route}': {error}",
                    filter.name()
                );
            }
        }
    }

    edits
}

/// Instantiates, calls one export, and reads the verdict back out of guest
/// memory. The `Store` dies with this function, taking the instance with it.
fn call(filter: &WasmFilter, export: &str, input: &Json) -> Result<Verdict, String> {
    let plugin = &filter.plugin;

    let mut store = Store::new(
        &plugin.engine,
        HostState {
            plugin: plugin.name.to_owned(),
            limits: StoreLimitsBuilder::new()
                .memory_size(plugin.memory_max_bytes)
                .build(),
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(plugin.fuel)
        .map_err(|error| format!("could not set the fuel budget: {error}"))?;

    let instance = plugin
        .instance_pre
        .instantiate(&mut store)
        .map_err(|error| format!("instantiation failed: {error}"))?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| "module does not export 'memory'".to_owned())?;

    let payload = serde_json::to_vec(input)
        .map_err(|error| format!("could not encode the request for the guest: {error}"))?;
    let length = i32::try_from(payload.len())
        .map_err(|_| "the request is too large to pass to a guest".to_owned())?;

    // The guest allocates in its own linear memory; the host only writes into
    // the region it is handed back.
    let alloc = instance
        .get_typed_func::<i32, i32>(&mut store, EXPORT_ALLOC)
        .map_err(|error| format!("'{EXPORT_ALLOC}' has the wrong signature: {error}"))?;
    let offset = alloc
        .call(&mut store, length)
        .map_err(|error| trap(plugin, EXPORT_ALLOC, &error))?;

    memory
        .write(&mut store, usize::try_from(offset).unwrap_or(usize::MAX), &payload)
        .map_err(|error| format!("'{EXPORT_ALLOC}' returned unusable memory: {error}"))?;

    let entry = instance
        .get_typed_func::<(i32, i32), i64>(&mut store, export)
        .map_err(|error| format!("'{export}' has the wrong signature: {error}"))?;
    let packed = entry
        .call(&mut store, (offset, length))
        .map_err(|error| trap(plugin, export, &error))?;

    let verdict = read_packed(&memory, &store, packed)?;
    serde_json::from_slice(&verdict)
        .map_err(|error| format!("'{export}' returned invalid JSON: {error}"))
}

/// A guest returns one i64 holding the pointer in the high half and the length
/// in the low half, so a single return value can describe a buffer.
fn read_packed(
    memory: &wasmtime::Memory,
    store: &Store<HostState>,
    packed: i64,
) -> Result<Vec<u8>, String> {
    let offset = ((packed as u64) >> 32) as usize;
    let length = (packed as u64 & 0xffff_ffff) as usize;

    if length == 0 {
        return Err("the guest returned an empty verdict".to_owned());
    }
    if length > MAX_VERDICT_BYTES {
        return Err(format!(
            "the guest returned {length} bytes, over the {MAX_VERDICT_BYTES} byte limit"
        ));
    }

    let data = memory.data(store);
    data.get(offset..offset + length)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "the guest returned a pointer outside its own memory".to_owned())
}

fn trap(plugin: &WasmPlugin, export: &str, error: &wasmtime::Error) -> String {
    match error.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::OutOfFuel) => format!(
            "'{export}' exhausted its fuel budget of {} (raise 'fuel' if the module \
             legitimately needs more)",
            plugin.fuel
        ),
        _ => format!("'{export}' trapped: {error}"),
    }
}

/// Fail closed by default. A filter that cannot run has not made its decision,
/// and forwarding anyway would quietly skip whatever it was there to enforce.
fn fail(filter: &WasmFilter, phase: &str, error: &str) -> Option<FilterOutcome> {
    eprintln!(
        "wasm plugin '{}' failed in the {phase} phase: {error}",
        filter.name()
    );

    if filter.plugin.fail_open {
        None
    } else {
        Some(FilterOutcome::Failed(format!(
            "plugin '{}' could not run",
            filter.name()
        )))
    }
}

fn into_outcome(filter: &WasmFilter, verdict: Verdict) -> FilterOutcome {
    if verdict.action == Action::Stop {
        let status = verdict.status.unwrap_or(403);
        if !(100..=599).contains(&status) {
            return match fail(filter, "request", &format!("returned invalid status {status}")) {
                Some(failure) => failure,
                None => FilterOutcome::Continue(HeaderEdits::default()),
            };
        }

        return FilterOutcome::Stop(Box::new(StopResponse {
            status,
            headers: valid_headers(filter, &verdict.headers),
            body: verdict.body,
        }));
    }

    let (set, remove) = header_edits(filter, &verdict);
    FilterOutcome::Continue(HeaderEdits { set, remove })
}

fn header_edits(filter: &WasmFilter, verdict: &Verdict) -> (Vec<(String, String)>, Vec<String>) {
    let remove = verdict
        .remove_headers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    (valid_headers(filter, &verdict.set_headers), remove)
}

/// A claim or a computed value containing CR/LF would splice headers
/// downstream, so anything that is not a legal header pair is dropped and
/// logged rather than forwarded.
fn valid_headers(filter: &WasmFilter, headers: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut valid: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, value)| {
            let ok = HeaderName::from_bytes(name.as_bytes()).is_ok()
                && HeaderValue::from_str(value).is_ok();
            if !ok {
                eprintln!(
                    "wasm plugin '{}' returned an invalid header '{name}'; dropping it",
                    filter.name()
                );
            }
            ok
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();

    // HashMap iteration order is not stable; a fixed order keeps what reaches
    // the upstream reproducible.
    valid.sort_by(|a, b| a.0.cmp(&b.0));
    valid
}

fn collect_headers(headers: &actix_web::http::header::HeaderMap) -> Map<String, Json> {
    let mut collected: Map<String, Json> = Map::new();

    for (name, value) in headers.iter() {
        let Ok(value) = value.to_str() else {
            // A binary header has no JSON representation; the guest simply
            // does not see it, and the proxy still forwards it untouched.
            continue;
        };
        let name = name.as_str().to_owned();

        match collected.get_mut(&name) {
            // Repeated headers are joined the way a recipient is required to
            // read them, so a guest sees one value per name.
            Some(Json::String(existing)) => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            _ => {
                collected.insert(name, Json::String(value.to_owned()));
            }
        }
    }

    collected
}

fn apply_to_json(headers: &mut Map<String, Json>, edits: &HeaderEdits) {
    for name in &edits.remove {
        headers.remove(name);
    }
    for (name, value) in &edits.set {
        headers.insert(name.to_owned(), Json::String(value.to_owned()));
    }
}

/// Route settings layered over plugin settings. Two objects merge key by key
/// so a route can change one field without restating the block; anything else
/// replaces outright, because there is no sensible way to merge a scalar with
/// a list.
fn merge(base: Json, overlay: Json) -> Json {
    match (base, overlay) {
        (Json::Object(mut base), Json::Object(overlay)) => {
            for (key, value) in overlay {
                let merged = match base.remove(&key) {
                    Some(existing) => merge(existing, value),
                    None => value,
                };
                base.insert(key, merged);
            }
            Json::Object(base)
        }
        (_, overlay) => overlay,
    }
}

/// Pulls the `settings:` block out of a params map and converts it to JSON,
/// which is what crosses the host/guest boundary.
fn settings_of(params: &HashMap<String, Yaml>, context: &str) -> Result<Json, String> {
    let Some(settings) = params.get("settings") else {
        return Ok(Json::Object(Map::new()));
    };

    match serde_json::to_value(settings) {
        Ok(value @ Json::Object(_)) => Ok(value),
        Ok(_) => Err(format!("{context} 'settings' must be a mapping")),
        Err(error) => Err(format!("{context} 'settings' is not representable as JSON: {error}")),
    }
}

fn read_memory(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<String> {
    let memory = caller.get_export("memory")?.into_memory()?;
    let offset = usize::try_from(ptr).ok()?;
    let length = usize::try_from(len).ok()?.min(4096);

    let data = memory.data(&caller).get(offset..offset + length)?.to_vec();
    String::from_utf8(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::HeaderMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A module that answers every call with `verdict`, verbatim. Its allocator
    /// hands out one fixed region, which is all a single call ever needs.
    fn module(verdict: &str, response_phase: bool) -> String {
        let escaped = verdict.replace('\\', "\\\\").replace('"', "\\\"");
        let length = verdict.len();
        let on_response = if response_phase {
            format!(
                "(func (export \"{EXPORT_ON_RESPONSE}\") (param i32 i32) (result i64) \
                 (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const {length})))"
            )
        } else {
            String::new()
        };

        format!(
            r#"(module
              (memory (export "memory") 2)
              (data (i32.const 16) "{escaped}")
              (func (export "{EXPORT_ALLOC}") (param i32) (result i32) (i32.const 4096))
              (func (export "{EXPORT_ON_REQUEST}") (param i32 i32) (result i64)
                (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const {length})))
              {on_response}
            )"#
        )
    }

    fn plugin(wat: &str, params: &str) -> Result<WasmPlugin, String> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let path = std::env::temp_dir().join(format!(
            "gillnet-plugin-{}-{}.wat",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, wat).expect("could not write the test module");

        let mut params: HashMap<String, Yaml> =
            yaml_serde::from_str(params).expect("invalid test params");
        params.insert("path".to_owned(), Yaml::String(path.display().to_string()));

        WasmRuntime::new()?.load(&PluginConfig {
            name: "test-plugin".to_owned(),
            plugin_id: "wasm-plugin".to_owned(),
            params,
        })
    }

    fn filter(verdict: &str) -> WasmFilter {
        let plugin = plugin(&module(verdict, false), "{}").expect("the module should load");
        WasmFilter::build(Arc::new(plugin), Json::Object(Map::new())).unwrap()
    }

    fn run(filter: &WasmFilter) -> FilterOutcome {
        on_request(
            std::slice::from_ref(filter),
            "test-route",
            "GET",
            "/thing",
            "",
            &HeaderMap::new(),
        )
    }

    #[test]
    fn route_settings_layer_over_plugin_settings() {
        let base = json!({"limit": 100, "burst": 5, "window": {"seconds": 60, "sliding": true}});
        let route = json!({"limit": 10, "window": {"seconds": 1}});

        // `burst` survives untouched and `window.sliding` survives the nested
        // merge, so a route can change one field without restating the block.
        assert_eq!(
            merge(base, route),
            json!({"limit": 10, "burst": 5, "window": {"seconds": 1, "sliding": true}})
        );
    }

    #[test]
    fn a_route_replaces_a_list_rather_than_appending_to_it() {
        let merged = merge(json!({"allow": ["a", "b"]}), json!({"allow": ["c"]}));
        assert_eq!(merged, json!({"allow": ["c"]}));
    }

    #[test]
    fn a_module_missing_the_abi_is_rejected_at_load() {
        let Err(error) = plugin("(module (memory (export \"memory\") 1))", "{}") else {
            panic!("a module with no entry point must not load");
        };
        assert!(error.contains(EXPORT_ALLOC), "unexpected error: {error}");
    }

    #[test]
    fn a_missing_module_file_is_a_startup_error() {
        let runtime = WasmRuntime::new().unwrap();
        let mut params = HashMap::new();
        params.insert("path".to_owned(), Yaml::String("/nope/absent.wasm".to_owned()));

        let Err(error) = runtime.load(&PluginConfig {
            name: "absent".to_owned(),
            plugin_id: "wasm-plugin".to_owned(),
            params,
        }) else {
            panic!("a module that is not there must not load");
        };
        assert!(error.contains("could not load module"), "unexpected: {error}");
    }

    #[test]
    fn a_continue_verdict_edits_headers() {
        let filter = filter(
            r#"{"action":"continue","setHeaders":{"X-Wasm":"ok"},"removeHeaders":["Cookie"]}"#,
        );

        let FilterOutcome::Continue(edits) = run(&filter) else {
            panic!("the filter should have continued");
        };
        // Both directions are lowercased, so proxy.rs can match them against
        // header names without caring how the guest spelled them.
        assert_eq!(edits.set, vec![("x-wasm".to_owned(), "ok".to_owned())]);
        assert_eq!(edits.remove, vec!["cookie".to_owned()]);
    }

    #[test]
    fn a_stop_verdict_answers_the_request() {
        let filter = filter(
            r#"{"action":"stop","status":429,"headers":{"Retry-After":"30"},"body":"slow down"}"#,
        );

        let FilterOutcome::Stop(stop) = run(&filter) else {
            panic!("the filter should have stopped the request");
        };
        assert_eq!(stop.status, 429);
        assert_eq!(stop.body, "slow down");
        assert_eq!(stop.headers, vec![("retry-after".to_owned(), "30".to_owned())]);
    }

    #[test]
    fn a_stop_without_a_status_is_a_forbidden() {
        let FilterOutcome::Stop(stop) = run(&filter(r#"{"action":"stop"}"#)) else {
            panic!("the filter should have stopped the request");
        };
        assert_eq!(stop.status, 403);
    }

    #[test]
    fn a_header_a_guest_could_splice_with_is_dropped() {
        let filter = filter(r#"{"action":"continue","setHeaders":{"x-ok":"fine","x-bad":"a\r\nInjected: yes"}}"#);

        let FilterOutcome::Continue(edits) = run(&filter) else {
            panic!("the filter should have continued");
        };
        assert_eq!(edits.set, vec![("x-ok".to_owned(), "fine".to_owned())]);
    }

    #[test]
    fn a_runaway_module_trips_its_fuel_budget() {
        let wat = format!(
            r#"(module
              (memory (export "memory") 1)
              (func (export "{EXPORT_ALLOC}") (param i32) (result i32) (i32.const 1024))
              (func (export "{EXPORT_ON_REQUEST}") (param i32 i32) (result i64)
                (loop $spin (br $spin))
                (i64.const 0))
            )"#
        );
        let plugin = plugin(&wat, "fuel: 100000").expect("the module should load");
        let filter = WasmFilter::build(Arc::new(plugin), Json::Object(Map::new())).unwrap();

        // Fail closed: the filter never reached a decision, so the request is
        // refused rather than quietly forwarded past whatever it enforced.
        let FilterOutcome::Failed(message) = run(&filter) else {
            panic!("an endless module must not be allowed to continue");
        };
        assert!(message.contains("test-plugin"), "unexpected: {message}");
    }

    #[test]
    fn fail_open_forwards_when_a_module_breaks() {
        let wat = format!(
            r#"(module
              (memory (export "memory") 1)
              (func (export "{EXPORT_ALLOC}") (param i32) (result i32) (i32.const 1024))
              (func (export "{EXPORT_ON_REQUEST}") (param i32 i32) (result i64) (unreachable))
            )"#
        );
        let plugin = plugin(&wat, "fail-open: true").expect("the module should load");
        let filter = WasmFilter::build(Arc::new(plugin), Json::Object(Map::new())).unwrap();

        let FilterOutcome::Continue(edits) = run(&filter) else {
            panic!("fail-open should forward the request");
        };
        assert!(edits.set.is_empty());
    }

    #[test]
    fn a_pointer_outside_guest_memory_is_refused() {
        let wat = format!(
            r#"(module
              (memory (export "memory") 1)
              (func (export "{EXPORT_ALLOC}") (param i32) (result i32) (i32.const 1024))
              (func (export "{EXPORT_ON_REQUEST}") (param i32 i32) (result i64)
                (i64.or (i64.shl (i64.const 4000000) (i64.const 32)) (i64.const 64)))
            )"#
        );
        let plugin = plugin(&wat, "{}").expect("the module should load");
        let filter = WasmFilter::build(Arc::new(plugin), Json::Object(Map::new())).unwrap();

        assert!(matches!(run(&filter), FilterOutcome::Failed(_)));
    }

    #[test]
    fn the_response_phase_runs_only_for_modules_that_export_it() {
        let verdict = r#"{"action":"continue","setHeaders":{"X-Phase":"response"}}"#;

        let without = filter(verdict);
        assert!(!without.has_response_phase());
        assert!(on_response(std::slice::from_ref(&without), "r", 200, &[]).set.is_empty());

        let with = plugin(&module(verdict, true), "{}").expect("the module should load");
        let with = WasmFilter::build(Arc::new(with), Json::Object(Map::new())).unwrap();

        assert!(with.has_response_phase());
        assert_eq!(
            on_response(std::slice::from_ref(&with), "r", 200, &[]).set,
            vec![("x-phase".to_owned(), "response".to_owned())]
        );
    }

    #[test]
    fn a_route_may_not_use_auth_params_on_a_wasm_plugin() {
        let plugin = Arc::new(plugin(&module(r#"{"action":"continue"}"#, false), "{}").unwrap());

        let reference = PluginReference {
            name: "test-plugin".to_owned(),
            params: Some(
                yaml_serde::from_str("roles: [admin]").expect("invalid test params"),
            ),
        };

        let Err(error) = WasmFilter::from_reference(plugin, &reference) else {
            panic!("'roles' means nothing to a module and must not look like it does");
        };
        assert!(error.contains("settings"), "unexpected: {error}");
    }

    #[test]
    fn repeated_request_headers_reach_a_guest_as_one_value() {
        let mut headers = HeaderMap::new();
        headers.append(HeaderName::from_static("accept"), HeaderValue::from_static("a"));
        headers.append(HeaderName::from_static("accept"), HeaderValue::from_static("b"));

        assert_eq!(collect_headers(&headers)["accept"], json!("a, b"));
    }
}
