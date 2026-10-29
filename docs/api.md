# Lua API reference

Load `local handler = require 'resty.peter_sslers'`. All calls use dot syntax,
not colon syntax. `_VERSION` is `1.0.0`; it also supplies administration response
headers and `server_version` fields. See the [README](../README.md) for setup and
failure behavior, and [connectivity](connectivity.md) for authentication/TLS
options. Configure the module once per worker; keep per-handshake configuration
stable because caches are keyed by canonical domain, not connection settings.

## Initialization

### `initialize()`

Optional `init_by_lua_block` hook. Logs initialization and returns `true`; it
allocates no worker cache.

### `initialize_worker(shared_ttl, worker_ttl, maxitems)`

Required in `init_worker_by_lua_block` before lookups, cache helpers, or admin
handlers. Creates the worker's mlcache instance with `cert_cache` and
`cert_cache_ipc`; both shared dictionaries must exist. Returns `true` or raises
on setup failure.

| Argument | Initial default | Meaning |
| --- | --- | --- |
| `shared_ttl` | 600 | Seconds for positive and negative shared entries; `0` means no shared expiry. Also used for the autocert lease. |
| `worker_ttl` | 60 | Seconds limiting L1 retention; `0` disables the worker cap, leaving the shared lifetime in effect. |
| `maxitems` | 200 | Maximum L1 entries, each a complete pair or absence. |

A worker entry uses the shorter shared lifetime and worker cap. With no shared
expiry, the worker cap still applies if enabled. Omitted/nil arguments retain
the current module settings, initially the defaults above. Reinitializing
replaces the worker L1; configure positive TTLs for normal operation.

### Connection configuration

| Function | Effect / return |
| --- | --- |
| `valkey_update_defaults(host, port, database, options)` | Alias of `redis_update_defaults`; updates the same datastore settings. No return value. Added in 1.0.0. |
| `redis_update_defaults(host, port, database, options)` | Sets endpoint/database; optional connection options added in 1.0.0. No return value. |
| `api_update_defaults(options)` | Replaces API connection options; no return value. Added in 1.0.0. |

The datastore's initial endpoint is `127.0.0.1:6379`, database `9`. Supply all
three endpoint arguments when overriding it. Omitting/nil datastore `options`
preserves connection options; `{}` restores defaults. API `options` must be a
table. Supplied tables replace, rather than merge with, previous options and
invalid options raise before the new configuration takes effect. Neither setter
flushes certificates. See the [options reference](connectivity.md#options).

## Certificate handler

### `set_ssl_certificate(redis_strategy, fallback_server, enable_autocert, cert_preferences)`

Call only in `ssl_certificate_by_lua*`. Uses canonical SNI to search worker L1,
shared L2, datastore, then API. Polls IPC first so cache writes/expiration become
visible before lookup. A valid pair is installed; absence, lookup errors,
invalid SNI, and busy/obsolete autocert attempts retain default credentials.
Clearing/installation errors explicitly abort the handshake. Normally returns
no value; errors are logged rather than returned to the caller.

| Argument | Meaning |
| --- | --- |
| `redis_strategy` | `nil` disables Valkey/Redis; `1` selects prime-1; `2` selects prime-2. Other values on a cache miss skip backend retrieval. |
| `fallback_server` | Full HTTP(S) Python admin root, without a trailing slash; `nil` disables API requests. |
| `enable_autocert` | `nil` uses ordinary GET lookups. **Every non-nil value, including `false`, enables POST provisioning.** |
| `cert_preferences` | Ordered array of API response field names; ignored by datastore queries. |

Default preferences:

```lua
{'certificate_signed__latest_multi', 'certificate_signed__latest_single'}
```

The first preference with string `fullchain.pem` and `private_key.pem` fields
is selected. PEM/key-match validation happens afterward; an invalid selected
pair does not cause another preference in that payload to be tried. HTTP 404
is cacheable absence; an HTTP-200 payload is authoritative absence only when
all requested preferences are explicitly JSON null and it has no error result,
instructions, or form errors. Other failures remain retryable, subject to
[retry cooldowns](connectivity.md#retry-cooldowns).

Ordinary lookup sends GET to
`{fallback_server}/domain/{domain}/config.json?openresty=1`. Autocert sends a form
POST with `domain_name` to
`{fallback_server}/api/domain/autocert.json?openresty=1`. Provisioning leases and
mlcache miss locking coordinate workers; lost-lease responses are discarded.
Cache/lease/validation behavior was revised in 1.0.0; the handler predates it.

## Administration

Both handlers run in `content_by_lua*`, require worker initialization, write
JSON with `Content-Type: application/json` and `x-peter-sslers: 1.0.0`, and return
no Lua value. They do not authenticate callers or restrict HTTP methods.
Configure access controls in Nginx; see the [administration example](../README.md#administration).

### `status_ssl_certs()`

Returns HTTP 200 with `result`, `note`, `keys`, `config`, `server`, and
`server_version`. `keys.valid`, `keys.invalid`, and `keys.autocert` list shared
status names, not verified certificate validity. The handler scans at most
1024 shared dictionary keys (including internal keys), considers `:c` metadata,
and checks that mlcache entries still exist for positive/negative status.
Pending autocert metadata is listed independently of certificate presence.
No PEM, keys, worker-local entries, or datastore records are returned.

`config.expiries` reports `ngx.shared.cert_cache` and `resty.lrucache` TTL
settings in seconds. `config.maxitems['resty.lrucache']` is the worker entry
limit. Status may omit domains because of dictionary pressure, scan limits, or
missing metadata; it is a diagnostic sample. mlcache-aware status is new in
1.0.0; the endpoint predates it.

### `expire_ssl_certs()`

Matches the **full** `ngx.var.request_uri` using `ngx.var.location` as prefix:

| Suffix | Action |
| --- | --- |
| `/domain/{domain}` | Delete the mlcache entry, invalidate L1 through IPC, and remove legacy/status keys for that domain. |
| `/all` | Purge `cert_cache`, including certificate entries, metadata, locks, cooldowns, and legacy entries; broadcast L1 purge. |

Use the exact canonical lowercase name without a trailing dot; the handler
does not normalize it. Query strings do not match. It does not remove datastore
records. Per-domain expiration retains the domain's autocert lease and retry
markers; an in-flight request may repopulate the cache. A full purge removes
leases, causing obsolete autocert responses to be discarded. Other in-flight
ordinary fetches may still complete after expiration.

Workers apply invalidation on their next certificate lookup. Return statuses
are 200 on success, 503 when deletion/purge/IPC fails, and 404 for unknown routes.
Success JSON includes `result`, `expired`, optional `domain`, `server`, and
`server_version`. A 503 body has `result` and `reason`; it does not include the
server/version fields. An invalidation error may follow a completed shared
write, so 503 does not imply that shared state was unchanged. Cross-worker
invalidation was added in 1.0.0; the endpoint predates it.

## Advanced and test helpers

These exports expose lower-level operations. They bypass parts of the main
handler and require callers to manage validation, canonical names, cache
coherence, and connection lifetime as indicated. Prefer the main handler for
normal certificate serving. Calls making network requests need a cosocket-capable
phase; cache helpers need `initialize_worker` first.

### Datastore helpers

| Function | Contract |
| --- | --- |
| `get_redcon()` | Return a connected `resty.redis` client, or `nil, error`; apply configured auth/TLS/database and isolate pools. Does not enforce cooldowns. |
| `redis_keepalive(redcon)` | Return a usable client to its pool with 10-second idle timeout and capacity 100; log errors, return no value. Do not reuse the client afterward. |
| `prime_1__query_redis(redcon, name)` | Read `d1:{name}` fields `c/p/i`, then pipeline GETs for `p:{p}`, `c:{c}`, `i:{i}`. Return cert PEM joined to chain with a newline, plus private key. |
| `prime_2__query_redis(redcon, name)` | HMGET `d2:{name}` fields `p/f` into private-key/fullchain PEM. |

Both query helpers return a pair table on success, `nil` on clean absence, or
`nil, error, backend_failure` on failure. The third result is truthy for a
transport/backend failure; record/command errors are domain-local. These helpers
do not normalize names, validate PEM, cache, or apply cooldowns. Close a client
after query failure; otherwise call `redis_keepalive`. Error classification and
prime-1 pipelining were added in 1.0.0.

### API helpers

`query_api_upstream(fallback_server, name, preferences)` and
`query_api_autocert(fallback_server, name, preferences)` make the GET and POST
requests described above with configured API options. They canonicalize names
and make no request for invalid names. They return a pair table, possibly
without `cert`/`pkey`, with `transient` and `backend_failure` metadata for valid
name lookups. Invalid names return an empty table without those flags.

They do not validate PEM/key matching, cache, enforce cooldowns, or acquire/fence
autocert leases. Unexpected client exceptions may propagate; the main handler
catches them. These functions predate 1.0.0; normalization, secure options, and
failure metadata were added in 1.0.0.

### Pair and cache helpers

| Function | Contract |
| --- | --- |
| `certificate_pairing()` | Return an empty table; absent `cert`/`pkey` fields represent no pair. |
| `certificate_pairing_pem_to_cdata(pem, output)` | Parse leaf-first `pem.cert` and private `pem.pkey`, verify matching, and return the supplied output table. Failure logs and clears both output fields. No hostname/date/trust checks. Matching added in 1.0.0. |
| `set_cert_sharedcache(name, pem)` | Store/validate a PEM pair through mlcache, update status metadata, and broadcast invalidation. Return `true` or `nil, error`. Failure deletes the entry/status; metadata-write failure only logs. Caller supplies a canonical name and string PEM fields. mlcache behavior added in 1.0.0. |
| `set_cert_lrucache(name, cdata_pair)` | Directly set one complete pair in this worker's L1 with worker TTL. No validation, L2 update, status update, or IPC; returns no value. Caller must supply an already validated pair and canonical name. |

The internal cache namespace and serialization are implementation details.
Directly editing shared entries or inserting unchecked cdata bypasses the main
handler's guarantees. Existing applications using old per-certificate/per-key
LRU keys must migrate to complete-pair entries for 1.0.0.
