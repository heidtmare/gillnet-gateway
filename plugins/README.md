# Writing a gillnet wasm-plugin

A `wasm-plugin` is a WebAssembly module the gateway calls on its way through a
request. It can read the request line and headers, change the headers that go
upstream, answer the request itself, and add headers to the response coming
back.

`header-policy/` is a complete working example in Rust. This document is the
contract it implements.

## Declaring one

The module is declared once, with base settings, and referenced by name from
any number of routes:

```yaml
plugins:
  - name: header-policy
    type: wasm-plugin
    params:
      path: ./plugins/header-policy/target/wasm32-unknown-unknown/release/header_policy.wasm
      settings:
        require: { x-api-version: "*" }
        set: { x-gateway: gillnet }

routes:
  - name: things
    url: my-service
    paths: [/things]
    plugins:
      - name: header-policy
        params:
          settings:
            require: { x-api-version: "2" }   # merged over the base
```

Route settings are merged over the plugin's at startup: two mappings merge key
by key, anything else replaces outright. Here the route tightens `require` and
keeps `set` untouched. `GET /registry/describe` reports the merged result for
each route, which is exactly what the module will be handed.

A self-registering service asks for the same thing with
`{"name": "header-policy", "settings": {...}}` in its route spec. It names a
plugin the gateway already has; it can never supply a module of its own.

## The ABI

A module exports:

| Export | Signature | Required |
|---|---|---|
| `memory` | — | yes |
| `gillnet_alloc` | `(i32) -> i32` | yes |
| `gillnet_on_request` | `(i32, i32) -> i64` | yes |
| `gillnet_on_response` | `(i32, i32) -> i64` | no |

and may import one host function, `gillnet.log(i32, i32)`, which writes a UTF-8
string (truncated at 4 KiB) to the gateway's log prefixed with the plugin name.
Nothing else is available: no clock, no filesystem, no network, no WASI.

A call goes:

1. The host calls `gillnet_alloc(len)` and writes `len` bytes of JSON at the
   returned offset.
2. The host calls the phase export with that offset and length.
3. The guest returns one `i64`: **the pointer in the high 32 bits, the length in
   the low 32 bits**. The host reads the verdict JSON from there.

The whole instance is torn down after the call, so a guest never has to free
anything — leak the buffer and move on.

### What the guest receives

Request phase:

```json
{
  "phase": "request",
  "route": "things",
  "method": "GET",
  "path": "/things/42",
  "query": "verbose=1",
  "headers": { "host": "api.example.com", "accept": "a, b" },
  "settings": { "...": "the merged settings for this route" }
}
```

Header names are lowercase. A header sent more than once arrives joined with
`", "`. A header whose value is not valid UTF-8 is not shown to the guest — the
proxy still forwards it untouched.

Response phase is the same shape with `"phase": "response"`, a `status`, the
response headers, and no method/path.

### What the guest returns

```json
{ "action": "continue", "setHeaders": { "x-gateway": "gillnet" }, "removeHeaders": ["cookie"] }
```

```json
{ "action": "stop", "status": 429, "headers": { "retry-after": "30" }, "body": "slow down\n" }
```

`action` defaults to `continue`. Unknown fields are ignored, so a module written
against a later revision still runs.

- **`continue`** forwards the request with those header edits applied. A header
  the guest sets belongs to the gateway: any copy the client sent is dropped
  before forwarding, so a filter's output cannot be spoofed.
- **`stop`** answers the client from the gateway; the upstream is never
  contacted, and later filters on the route do not run. `status` defaults to 403.
- A header name or value that is not legal HTTP (a CR or LF in a value, say) is
  dropped and logged rather than forwarded.

In the response phase only `setHeaders` and `removeHeaders` apply. The body is
already streaming to the client by then, so there is nothing left to stop.

## Ordering and failure

Filters run in the order the route lists them, and always **after** the route's
auth plugins — a module never sees a request that failed authentication. Each
filter sees the header edits the ones before it made.

Every call gets a fresh instance, so a module cannot carry state from one
request into the next. If you need shared state, keep it upstream.

Execution is bounded by `fuel` and memory by `memory-max-bytes`. A module that
loops forever or allocates without bound trips its budget and fails the request
rather than taking a worker down.

When a module fails — traps, runs out of fuel, returns unparseable JSON — the
default is to **fail closed**: the filter reached no decision, so the request is
refused with 500 rather than forwarded past whatever the filter was enforcing.
`fail-open: true` inverts that, and is appropriate only for filters that
decorate (a header stamp, telemetry) rather than gate.

A response-phase failure is always logged and ignored: there is no way to refuse
a response that is already on the wire.

## Building the example

```sh
rustup target add wasm32-unknown-unknown
cd plugins/header-policy
cargo build --release --target wasm32-unknown-unknown
```

The module lands at
`target/wasm32-unknown-unknown/release/header_policy.wasm`.

Any language that compiles to core WebAssembly works — the ABI is four exports
and JSON, with no component-model tooling required.
