# lua-resty-peter_sslers

Dynamic TLS certificates for OpenResty, backed by the
[peter_sslers Certificate Manager](https://github.com/aptise/peter_sslers).
The package has been used in production since 2016. This checkout prepares
**1.0.0**; see [CHANGES.txt](CHANGES.txt) for release notes and
[versioning](#versioning) for Python backend compatibility.

During the SNI phase, the handler searches the worker cache, shared cache,
Valkey/Redis, and Python API in that order. It can also request a new certificate
through the API's autocert endpoint. Each backend is optional. Valkey is the
preferred datastore; Redis uses the same client and certificate layouts.

## Installation

Install or upgrade through OPM:

```sh
opm get aptise/lua-resty-peter_sslers
opm upgrade aptise/lua-resty-peter_sslers
```

Use the permissions required by your OpenResty installation. A published OPM
package may lag this checkout; check `require('resty.peter_sslers')._VERSION`.
The package depends on OpenResty, `lua-resty-http`, `lua-resty-mlcache`, and
`lua-resty-openssl`; OpenResty supplies `lua-resty-redis` and `lua-resty-lrucache`.
OPM dependencies are declared in [dist.ini](dist.ini).

## Configuration

Define both shared dictionaries and initialize each worker before lookups:

```nginx
http {
    lua_shared_dict cert_cache 1m;
    lua_shared_dict cert_cache_ipc 100k;
    lua_code_cache on;

    init_by_lua_block {
        require 'resty.core'
        require('resty.peter_sslers').initialize()
    }
    init_worker_by_lua_block {
        local handler = require 'resty.peter_sslers'
        -- Shared TTL, worker TTL cap (seconds), worker entry limit.
        handler.initialize_worker(600, 60, 200)
        -- Optional: override the default 127.0.0.1:6379, database 9.
        -- handler.valkey_update_defaults('127.0.0.1', 6379, 9, {})
    }

    server {
        listen 443 ssl;
        server_name example.com;
        ssl_certificate /path/to/default/fullchain.pem;
        ssl_certificate_key /path/to/default/privkey.pem;

        ssl_certificate_by_lua_block {
            require('resty.peter_sslers').set_ssl_certificate(
                1, 'http://127.0.0.1:6543/.well-known/admin', nil)
        }
    }
}
```

The `set_ssl_certificate` arguments select the datastore layout, API admin root,
and autocert mode. `redis_strategy` accepts `1` or `2` for either Valkey or Redis;
`nil` disables the datastore. A `nil` API root disables the API. Keep the API
root free of a trailing slash. Hostname-based backends need a suitable Nginx
`resolver`.

Autocert is disabled only by `nil`: **any non-nil value, including `false`,
enables provisioning**. The optional fourth argument is an ordered array of API
certificate fields, defaulting to multi-domain then single-domain certificates.
See the [API reference](docs/api.md) for signatures, return values, and phases.

The datastore defaults to plaintext without authentication. Configure datastore
password/ACL authentication, TLS, client certificates, timeouts, and retry
cooldowns through `valkey_update_defaults` (alias `redis_update_defaults`).
Configure the API independently through `api_update_defaults`; use an `https://`
URL to enable API TLS. The [connectivity guide](docs/connectivity.md) contains
the options table, trust configuration, compatibility requirements, and a secure
example.

## Caching and invalidation

`lua-resty-mlcache` manages the two cache tiers and coalesces concurrent misses:

| Tier | Stored value | Default lifetime / capacity |
| --- | --- | --- |
| Worker L1 | Validated certificate/key cdata pair, or absence | 60-second TTL cap; 200 entries |
| Shared L2 (`cert_cache`) | One packed PEM pair per domain, or absence | 600 seconds; dictionary size controls capacity |
| IPC (`cert_cache_ipc`) | Cross-worker invalidation events | Separate shared dictionary; example size 100k |

An L1 entry holds a complete pair, so 200 entries can hold up to 200 pairs;
negative entries consume capacity too. L1 expiry is bounded by the shared entry's
remaining lifetime and the worker cap. `initialize_worker` configures these
TTLs and the L1 limit. Shared status flags, locks, and retry markers also consume
`cert_cache` space; size it for your certificate chains and domain count.

Shared memory survives configuration reloads; worker L1 caches do not. Writes,
per-domain expiration, and full purges broadcast invalidation. Each worker polls
IPC before its next certificate lookup, so normal invalidation does not wait
for its LRU TTL. There is no stale-certificate fallback after expiry. If storing
a valid backend result fails under memory pressure, the current handshake can
still use it; shared storage is not guaranteed.

Version 1.0.0 uses a new mlcache namespace and does not reuse legacy PEM/negative
entries as certificate cache entries. It repopulates from the backends; old
entries may occupy shared memory until expiry or a full purge. Plan for that
cold-cache load when upgrading from 0.x.

## Lookup and failure behavior

Names are normalized to lowercase with one final dot removed. Invalid or absent
SNI leaves the configured default certificate in place without a backend lookup.
Use IDNA ASCII names for internationalized domains.

A candidate must parse as PEM and its private key must match the **first**
certificate in the chain. Invalid or mismatched datastore pairs allow API
fallback. Validation runs on backend fetches and shared-cache loads; worker L1
hits reuse the validated pair. It does not check hostname coverage, expiration,
or trust, so backends remain responsible for supplying appropriate material.

Only authoritative absence creates a negative certificate entry: a clean miss
from all enabled sources, an API 404, or an HTTP-200 payload explicitly marking
all requested preferences as JSON null without an API error/instructions/form
errors. Transport errors, malformed responses, incomplete datastore records,
and invalid certificate pairs remain retryable.

Failures start a separate, shared cooldown: one second by default, independently
configurable per backend with `retry_backoff` (0–60 seconds; `0` disables it).
Backend outages affect that backend; bad domain data affects only that domain.
Cached pairs and healthy API fallback remain available. See
[retry cooldowns](docs/connectivity.md#retry-cooldowns) for precise classification.

Ordinary API lookups use GET; autocert uses a form POST. Both include
`openresty=1` to request the Python server's write-through behavior. Autocert
uses an atomic shared lease and ownership token so busy or obsolete attempts
leave defaults in place rather than publish stale responses. The lease uses
the shared TTL, independently of the retry cooldown.

If clearing or installing credentials fails, the handler logs the error and
explicitly aborts the TLS handshake. It stops at the failed step and cannot
restore defaults after clearing begins.

## Administration

Invoke these handlers in a content phase, with authentication or network access
controls appropriate for your deployment:

```nginx
location /.peter_sslers/nginx/shared_cache/status {
    auth_basic 'peter_sslers-nginx';
    auth_basic_user_file /path/to/peter_sslers-nginx.htpasswd;
    content_by_lua_block {
        require('resty.peter_sslers').status_ssl_certs()
    }
}
location /.peter_sslers/nginx/shared_cache/expire {
    auth_basic 'peter_sslers-nginx';
    auth_basic_user_file /path/to/peter_sslers-nginx.htpasswd;
    content_by_lua_block {
        require('resty.peter_sslers').expire_ssl_certs()
    }
}
```

| Route suffix below `…/shared_cache` | Effect |
| --- | --- |
| `/status` | Sample shared domain status and report TTL/capacity settings; excludes worker L1 and datastore contents. |
| `/expire/domain/example.com` | Remove that domain's cached pair/absence and broadcast L1 invalidation. |
| `/expire/all` | Purge `cert_cache`, including locks and cooldowns, and broadcast L1 purge. |

Per-domain expiration uses the exact lowercase name without a trailing dot;
query strings do not match. It retains provisioning locks and cooldowns and
does not delete datastore records. Status scans at most 1024 dictionary keys,
including internal keys, so it is a diagnostic sample rather than an inventory.
The [API reference](docs/api.md#administration) describes response fields and
failure statuses.

The [example scripts](examples) invoke these library functions. Use them with
matching `*_by_lua_file` directives or call the module directly as above;
`require` caches modules, so do not require an example script for repeated
request-specific work.

## Development and debugging

Run from the repository root. The preferred complete test run starts isolated
Valkey and authenticated Python HTTP/TLS/mTLS fixtures and checks cleanup:

```sh
opm get ledgetech/lua-resty-http thibaultcha/lua-resty-mlcache fffonion/lua-resty-openssl
cpanm Test::Nginx
TEST_NGINX_SERVER_PORT=19840 make test-secure
TEST_NGINX_SERVER_PORT=19840 make test-secure BACKEND=redis
```

Install Python 3, the `openssl` command, and a TLS-enabled `valkey-server` or
`redis-server`. See [secure test instructions](t/security/README.md) for focused
runs, parallel fixture verification, and nonstandard Perl library paths.

`make test` runs against a dedicated existing datastore, defaulting to
`127.0.0.1:6379`, and skips fixture-dependent security/network cases. Fixtures
use database 9 (security cases also use 8); `REDIS_HOST` and `REDIS_PORT` override
the existing datastore endpoint. Tests create and remove namespaced keys; avoid
using a production datastore. The HTTP harness defaults to unprivileged port
1984; `TEST_NGINX_SERVER_PORT` changes both its listener and local API URLs.
TLS tests use Unix sockets.

Use `OPENRESTY_PREFIX=/path/to/openresty` with make, or `TEST_NGINX_BINARY` to
select Nginx directly. Checkouts containing spaces automatically use temporary
runtime directories, retained for log inspection. An explicit
`TEST_NGINX_SERVROOT` must be a suitable path without spaces. Different ports
alone do not isolate shared runtime paths or every external fixture; prefer the
isolated runner. See [test design notes](t/certificate_serving/README.md).

The handler logs initialization at NOTICE, cache/backend activity at DEBUG,
and errors at ERR. Shorter TTLs can help diagnose refresh behavior, for example
`initialize_worker(5, 1, 100)`. Status reports shared state; it cannot enumerate
a worker's parsed pairs. For linting and coverage:

```sh
luacheck lib --no-unused
make coverage
```

Install `luacheck` and `luacov` separately. Retained
[development benchmarks](benchmarks/README.md) compare datastore connections
and lookup strategies; run `make benchmark` to reproduce them.

## Versioning

Versions use **MAJOR.MINOR.PATCH** semantic versioning for the documented Lua
API and supported behavior:

- **MAJOR** changes may break existing callers or deployment requirements.
- **MINOR** changes add functionality while keeping the Lua API compatible.
- **PATCH** changes fix bugs or documentation without intentional API breaks.

Backend protocol compatibility is an additional requirement: this package's
major/minor series is paired with the same `peter_sslers` major/minor series.
Patch numbers may differ. A compatible Lua API alone does not imply that a
new Python backend minor series is supported; upgrade the paired packages
together when moving to another minor series.

| Python `peter_sslers` | Lua package | Supported pairing |
| --- | --- | --- |
| 1.0.0 | 1.0.0 | Yes |
| 1.0.0 | 1.0.1 | Yes; patch versions may differ |
| 1.0.1 | 1.0.0 | Yes; patch versions may differ |
| 1.1.x | 1.0.x | No; major/minor series differ |
| 1.0.x | 1.1.x | No; major/minor series differ |

For the Python API, **1.0.0 requires `peter_sslers >= 1.0.0, < 1.1.0`** under
this pairing policy. Older requirements were `peter_sslers >= 0.5.0` for Lua
0.5.0, `>= 0.4.0, < 0.5.0` for Lua 0.4.0, and `< 0.4.0` for earlier releases.
Datastore-only deployments do not make Python API requests but must use the
supported prime-1 or prime-2 data layout.

The exported `_VERSION`, administration response headers, and JSON
`server_version` identify the Lua package. Version 1.0.0 establishes the current
API contract, including secure connectivity, mlcache invalidation, and retry
cooldowns. Advanced/test helpers are documented separately in the API reference;
applications should normally use the initialization, connection configuration,
certificate handler, and administration entry points.

## Author and license

Jonathan Vanasco <jonathan@findmeon.com>. Originally developed in
[peter_sslers](https://github.com/aptise/peter_sslers). Tests draw on
`lua-resty-http` and the OpenResty test suites.

Licensed under the MIT License; see [LICENSE.txt](LICENSE.txt).
