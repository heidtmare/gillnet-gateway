//! An example gillnet wasm-plugin: header policy.
//!
//! Shows the whole ABI in one file. The plugin checks that required headers are
//! present on the way in, stamps headers onto the upstream request, and adds
//! headers to the response on the way out. Everything it does comes from the
//! `settings` the gateway hands it, so the same module serves every route that
//! references it with different settings.
//!
//! Build with:
//!
//!   cargo build --release --target wasm32-unknown-unknown
//!
//! and point a `wasm-plugin` at
//! `target/wasm32-unknown-unknown/release/header_policy.wasm`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// Without this the import lands in the default `env` module and the gateway,
// which offers `gillnet.log`, will refuse to link the module at startup.
#[link(wasm_import_module = "gillnet")]
extern "C" {
    // The one thing the host offers. Everything else -- clock, network,
    // filesystem -- is deliberately absent.
    #[link_name = "log"]
    fn host_log(ptr: i32, len: i32);
}

fn log(message: &str) {
    unsafe { host_log(message.as_ptr() as i32, message.len() as i32) }
}

/// The host writes its JSON into the region this returns. The buffer is leaked
/// on purpose: the host tears down the whole instance after the call, so there
/// is nothing to reclaim and no allocator bookkeeping worth the code size.
#[no_mangle]
pub extern "C" fn gillnet_alloc(len: i32) -> i32 {
    let mut buffer = Vec::<u8>::with_capacity(len.max(0) as usize);
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);

    pointer as i32
}

#[no_mangle]
pub extern "C" fn gillnet_on_request(ptr: i32, len: i32) -> i64 {
    let Some(request) = read::<Request>(ptr, len) else {
        return respond(&Verdict::failed("the host sent JSON this plugin cannot read"));
    };
    let settings = request.settings;

    for (header, expected) in &settings.require {
        let header = header.to_ascii_lowercase();
        let actual = request.headers.get(&header).map(String::as_str);

        // "*" asks only that the header be there at all.
        let satisfied = match (actual, expected.as_str()) {
            (Some(_), "*") => true,
            (Some(actual), expected) => actual == expected,
            (None, _) => false,
        };
        if !satisfied {
            log(&format!("{} rejected: '{header}' is not as required", request.path));
            return respond(&Verdict {
                action: "stop",
                status: Some(settings.deny_status()),
                headers: BTreeMap::new(),
                body: format!("'{header}' is required on this route\n"),
                ..Verdict::default()
            });
        }
    }

    respond(&Verdict {
        set_headers: settings.set,
        remove_headers: settings.strip,
        ..Verdict::default()
    })
}

#[no_mangle]
pub extern "C" fn gillnet_on_response(ptr: i32, len: i32) -> i64 {
    let Some(response) = read::<Response>(ptr, len) else {
        return respond(&Verdict::default());
    };

    respond(&Verdict {
        set_headers: response.settings.response_set,
        ..Verdict::default()
    })
}

/// What the host sends in the request phase. Fields this plugin does not use
/// are simply not declared; serde ignores the rest.
#[derive(Deserialize)]
struct Request {
    path: String,

    #[serde(default)]
    headers: BTreeMap<String, String>,

    #[serde(default)]
    settings: Settings,
}

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    settings: Settings,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Settings {
    /// Header name -> required value, or "*" for "must be present".
    require: BTreeMap<String, String>,

    /// Headers stamped onto the request before it goes upstream.
    set: BTreeMap<String, String>,

    /// Headers stripped from the request.
    strip: Vec<String>,

    /// Headers added to the response on the way back.
    #[serde(rename = "response-set")]
    response_set: BTreeMap<String, String>,

    #[serde(rename = "deny-status")]
    deny_status: u16,
}

impl Settings {
    /// `Default` gives 0, which is not a status a gateway can send.
    fn deny_status(&self) -> u16 {
        match self.deny_status {
            0 => 403,
            status => status,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Verdict {
    action: &'static str,

    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,

    set_headers: BTreeMap<String, String>,
    remove_headers: Vec<String>,
    headers: BTreeMap<String, String>,
    body: String,
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            action: "continue",
            status: None,
            set_headers: BTreeMap::new(),
            remove_headers: Vec::new(),
            headers: BTreeMap::new(),
            body: String::new(),
        }
    }
}

impl Verdict {
    /// The gateway fails the request closed on a malformed verdict, so saying
    /// so explicitly is clearer than trapping.
    fn failed(reason: &str) -> Self {
        log(reason);
        Self {
            action: "stop",
            status: Some(500),
            body: format!("{reason}\n"),
            ..Self::default()
        }
    }
}

fn read<T: for<'a> Deserialize<'a>>(ptr: i32, len: i32) -> Option<T> {
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) };
    serde_json::from_slice(bytes).ok()
}

/// Packs the verdict's pointer into the high half of the return value and its
/// length into the low half, which is how the host is told where to read.
fn respond<T: Serialize>(verdict: &T) -> i64 {
    let json = serde_json::to_vec(verdict).unwrap_or_else(|_| b"{\"action\":\"continue\"}".to_vec());

    let boxed = json.into_boxed_slice();
    let len = boxed.len() as i64;
    let ptr = Box::leak(boxed).as_ptr() as i64;

    (ptr << 32) | len
}
