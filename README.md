# lua-resty-peter_sslers

Lua support for the [peter_sslers Certificate Manager](https://github.com/aptise/peter_sslers)
in OpenResty.

# Status

This package has been used in production since 2016.

This README describes the current checkout, including unreleased features in
[CHANGES.txt](CHANGES.txt). Released OPM packages may not yet include the new
secure-connectivity configuration APIs.

The `0.5.0` release requires `peter_sslers >= 0.5.0`

The `0.4.0` release requires `peter_sslers >= 0.4.0, <0.5.0`

Earlier releases require `peter_sslers < 0.4.0`


# Installation

Install with OPM:

    sudo opm install aptise/lua-resty-peter_sslers

To upgrade:

    sudo opm upgrade aptise/lua-resty-peter_sslers


## Synopsis

`lua-resty-peter_sslers` is a library that can be used in an OpenResty/Nginx
environment to dynamically serve the correct SSL certificate for a given domain.

Working alongside https://github.com/aptise/peter_sslers , this package will
load existing certificates or perform an "autocert" to provision a new one.

It supports both the prime cache types 1 & 2 of `peter_sslers`

It supports "autocert" functionality with `peter_sslers`

It is implemented as a library with some example scripts to invoke it.

* core library
  * `peter_sslers.lua`

Examples can be found in the `examples` directory, as well the extensive
unit tests

* examples
  * `ssl_certhandler-lookup.lua`
  * `ssl_certhandler-expire.lua`
  * `ssl_certhandler-status.lua`

The `-lookup.lua`, `-expire.lua`,  `-status.lua` scripts can be copied into an
nginx/openresty server block. For reference, look at the test suite.

Valkey is the preferred datastore backend; Redis remains supported. Both use
`lua-resty-redis` and the same prime-1/prime-2 certificate formats. Existing
Redis configuration calls continue to work.

The default datastore is `127.0.0.1:6379`, database `9`, without TLS or
authentication. Override it in worker initialization:

```lua
handler.valkey_update_defaults(host, port, database, options)
-- Equivalent backward-compatible name:
handler.redis_update_defaults(host, port, database, options)
```

The optional fourth argument configures password/ACL authentication, TLS,
client certificates, timeouts, and retry cooldowns. Configure the Python backend
separately with
`handler.api_update_defaults(options)` for Basic/Bearer authentication, HTTPS
verification, client certificates, timeouts, and retry cooldowns. Use an
`https://` fallback URL to enable API TLS.

See [Valkey, Redis, and secure API connections](docs/connectivity.md) for the
options reference, runtime requirements, trusted-CA setup, and a complete
configuration example.

The datastore is optional. Set `redis_strategy` to `nil` to query the API
directly, or to `1` or `2` to select a datastore certificate format. The argument
name applies to both Valkey and Redis.

### Pyramid Fallback

To use the Peter SSlers Pyramid fallback for querying domains or autocert
functionality, the following library is used:

* [lua-resty-http](https://github.com/ledgetech/lua-resty-http)

Successful API lookups are cached. Missing certificates can produce negative
cache entries. Transport failures and HTTP statuses other than 200 and 404 do
not create negative entries, so a subsequent handshake can retry after any active
retry cooldown. Malformed JSON, incomplete certificate fields, and API error
payloads also permit retries.
An HTTP-200 response explicitly setting every requested certificate preference
to JSON null can be negatively cached when it has no error, instructions, or
form-errors fields. HTTP 404 remains a cacheable absence. Invalid PEM is rejected
before caching and does not create a negative entry. Unexpected diagnostic field
types are logged safely without aborting lookup.

Fallback API requests include `openresty=1` to request write-through cache
behavior from the Pyramid app. Debug messages are written to the Nginx log.

### Caching Note

In order to maximize performance there are 2 layers of caching WITHIN
Nginx/OpenResty:

* Certificates are cached in a LRU cache within a given Worker in the native
  CDATA format for the configured LRU duration (default 60 seconds)
* Certificates are cached across all Workers in PEM format for
  the configured shared-cache duration (default 600 seconds)

Set these durations through `initialize_worker`. The LRU limit counts entries,
not domains: a certificate and its key occupy two entries, so the default of
200 holds at most 100 complete pairs.

The shared dictionary stores a complete PEM pair in one entry for consistent
reads across workers. Individual certificate and key entries are also retained
for status compatibility. Allow space for both representations; `100k` in the
example is only a starting point. A failed shared-cache write is logged and
invalidates the cached pair; the current request can still use the retrieved
certificate in its worker cache.

Shared dictionary contents survive a configuration reload. Worker LRU caches
belong to their individual workers. Expiration endpoints affect only shared
memory, so a worker may continue serving its cached certificate until its LRU
TTL expires. Choose the LRU duration to match the acceptable renewal delay.

On upgrade, old shared-cache certificate entries without the complete-pair
entry are treated as misses and repopulated from the backends. Existing negative
markers remain usable until they expire or are cleared.

## Usage

Configure the shared dictionary and initialization hooks in the `http` context:

```nginx
http {
    lua_shared_dict cert_cache 100k;
    lua_code_cache on;

    init_by_lua_block {
        require "resty.core"
        require("resty.peter_sslers").initialize()
    }
    init_worker_by_lua_block {
        require "resty.core"
        local handler = require "resty.peter_sslers"
        -- Shared-cache TTL, worker LRU TTL, worker LRU entry limit.
        handler.initialize_worker(600, 60, 200)
        -- Optional: select Valkey or Redis and configure its connection.
        -- handler.valkey_update_defaults("127.0.0.1", 6379, 9, {})
    }

    server {
        listen 443 ssl;
        server_name example.com;
        ssl_certificate /path/to/default/fullchain.pem;
        ssl_certificate_key /path/to/default/privkey.pem;

        ssl_certificate_by_lua_block {
            local handler = require "resty.peter_sslers"
            local redis_strategy = 1 -- nil disables Redis; 1 and 2 select its format.
            local fallback_server = "http://127.0.0.1:6543/.well-known/admin"
            local enable_autocert = nil -- Any non-nil value enables provisioning.
            handler.set_ssl_certificate(redis_strategy, fallback_server, enable_autocert)
        }
    }
}
```

`initialize` currently logs initialization. Call `initialize_worker` in each
worker before certificate lookups. Its optional arguments default to 600
seconds, 60 seconds, and 200 entries, respectively.

Pass `nil` for `fallback_server` to disable the API. To disable autocert, pass
`nil`, not `false`: the current interface treats every non-nil value as enabled.
The optional fourth argument to `set_ssl_certificate` is an ordered array of
API certificate fields. Its default is:

```lua
{"certificate_signed__latest_multi", "certificate_signed__latest_single"}
```

The core module is `lib/resty/peter_sslers.lua`. Use the handler examples
inside the corresponding Nginx Lua phase, such as `ssl_certificate_by_lua_block`
or `content_by_lua_block`, or with the matching `*_by_lua_file` directive. The
examples execute request-specific work; load the library with `require` and
invoke its functions on each request rather than requiring an example script
as a cached module.

### examples/ssl_certhandler-expire.lua

The Nginx shared memory cache persists across configuration reloads. These
endpoints clear cached values without requiring a full server restart.

A simple example is provided with `examples/ssl_certhandler-expire.lua`,
which can be invoked within Nginx as-is rather easily:

````
    server {
        listen 443 ssl default_server;
        ...
        location  /.peter_sslers  {
            auth_basic  "peter_sslers-nginx";
            auth_basic_user_file  /path/to/peter_sslers-nginx.htpasswd;
			location  /.peter_sslers/nginx/shared_cache/expire  {
				content_by_lua_block  {
					-- requirements
					local ssl_certhandler = require "resty.peter_sslers"

					-- alias functions
					local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs
					ssl_certhandler_expire()
				}
			}
		}
	}
````

The expiration handler uses the current Nginx `$location` value as its route
prefix. With the location shown above, it provides these routes:

* `/.peter_sslers/nginx/shared_cache/expire/all` flushes the shared dictionary.
* `/.peter_sslers/nginx/shared_cache/expire/domain/{DOMAIN}` removes the complete
  pair and individual certificate/key entries for that domain.

Use the lowercase domain without a trailing dot for per-domain expiration.
Avoid query strings: routing currently matches the full request URI.
Successful operations return HTTP 200 with a JSON `result` of `success`.
Unknown routes return HTTP 404. Neither operation clears worker LRU caches or
Redis. The per-domain route also leaves any in-progress autocert lock intact;
flushing the entire dictionary removes locks along with cached certificates.

The Pyramid component can query these endpoints automatically for you.


### examples/ssl_certhandler-status.lua

The status route lists up to 1024 shared-dictionary keys and reports cache
configuration. It does not inspect worker LRU caches or validate stored PEM.

````
    server {
        listen 443 ssl default_server;
        ...
        location  /.peter_sslers/nginx  {
            auth_basic  "peter_sslers-nginx";
            auth_basic_user_file  /path/to/peter_sslers-nginx.htpasswd;
			location  /.peter_sslers/nginx/shared_cache/status  {
				content_by_lua_block  {
					-- requirements
					local ssl_certhandler = require "resty.peter_sslers"

					-- alias functions
					local ssl_certhandler_status = ssl_certhandler.status_ssl_certs
					ssl_certhandler_status()
				}
			}
		}
	}
````
	
### examples/ssl_certhandler-lookup.lua

This example enables autocert provisioning:

````
        ssl_certificate_by_lua_block  {
            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"

            -- alias functions
            local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate

            local redis_strategy = 1
            local fallback_server = 'http://127.0.0.1:6543/.well-known/admin'
            local enable_autocert = 1
            ssl_certhandler_set(redis_strategy, fallback_server, enable_autocert)
        }
````


### Fully configured example

A fully configured example is available in the main peter_sslers repo:

   * https://github.com/aptise/peter_sslers/blob/master/tools/nginx_conf/enabled.conf

### Lookup and failure behavior

For each handshake, the handler checks the worker LRU, the shared dictionary,
Valkey/Redis if enabled, and finally the API if configured. Certificate and key
PEM must parse, and the private key must match the leaf certificate, before a
backend result is cached. Invalid or mismatched datastore pairs allow the API
fallback to run. Connection, authentication, database-selection, and
command errors reject the affected datastore connection. Command errors,
wrong-type keys, partial records, and missing referenced certificate parts can
fall through to the API and remain retryable; only an all-null domain lookup is
a clean datastore miss.

SNI names are lowercased and one final dot is removed. Names must use ASCII DNS
labels of at most 63 characters and total at most 253 characters after
normalization. Letters, digits, and internal hyphens are accepted. Use IDNA
ASCII form for internationalized names. Missing or rejected SNI names leave the
configured default certificate in place without querying a backend.

Without autocert, the API receives a GET at
`{fallback_server}/domain/{domain}/config.json?openresty=1`. With autocert, it
receives a form POST containing `domain_name` at
`{fallback_server}/api/domain/autocert.json?openresty=1`.

Autocert uses an atomic shared-dictionary lock plus a pending marker. A request
that cannot acquire the lock returns with the default certificate rather than
waiting for provisioning. Each attempt has an ownership token, and the lock is
held through cache publication. After the API call and PEM parsing, a request
that detects a lost lease discards its response rather than overwriting a newer
certificate or releasing another attempt's lock. Exceptions release a lock only
while the request still owns it. The lock lease uses the shared-cache TTL
(600 seconds by default); expiry, dictionary flushes, and eviction can permit a
replacement attempt while the original API request is still running.

A negative cache entry leaves the default certificate in place and suppresses
backend lookups until it expires or is cleared. A worker can retain a negative
entry for its LRU TTL after the shared marker expires. Datastore connection and
command errors, API transport failures, malformed API responses,
non-200/non-404 API responses, and invalid backend PEM do not create a new
negative entry. Failed backends instead receive a short cooldown shared across
workers: one second by default, configured independently for the datastore and
API with `retry_backoff` (0–60 seconds; `0` disables it). Cached certificates
remain available, and datastore cooldowns still allow API fallback. Invalid
domain data cools down only that domain. See the
[retry cooldown reference](docs/connectivity.md#retry-cooldowns)
for failure classification and recovery behavior. There is no stale-certificate
fallback after cache expiration.

Certificate/key matching uses `lua-resty-openssl` when loading a pair from a
backend or shared cache into a worker. Worker LRU hits reuse the validated pair.
Mismatched pairs leave the default credentials untouched and do not create a
negative cache entry. Invalid shared-cache material is also rejected before
installation, including entries published by an older worker.

These checks do not establish hostname coverage, expiration, or certificate
trust. Backends must supply appropriate certificate material, with the leaf
certificate first in the PEM chain. A failure clearing default credentials or
installing a certificate or key is logged and explicitly aborts the TLS
handshake. Installation stops at the failed step; there is no rollback to the
default credentials after clearing begins.

### Integration/Debugging HowTo

Various levels of information are sent to the following debug levels of Nginx.
Changing the Nginx debug level will expose more data

* ERR
* NOTICE
* DEBUG

Notice how a worker is initialized:

	-- cert_cache_duration, lru_cache_duration, lru_maxitems
	ssl_certhandler.initialize_worker(90, 30, 100)
	
For debugging you may want to lower these to shorten the LRU cache to a
negligible number

	ssl_certhandler.initialize_worker(5, 1, 100)
	
The "/status" and "/expire" routes only show information in the shared cache --
information is cached into each worker's own LRU cache and is not available to
these routes.  If "/expire" is used, a domain will be removed from the shared
cache and "/status" route... but may still be in a worker's LRU.


Check the status:

	curl -k https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/status

expire

	curl -k https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/expire/domain/example.com
	
	
### Tests

Run commands from the repository root. Install OpenResty, `lua-resty-http`,
`lua-resty-mlcache`, `lua-resty-openssl`, Valkey (preferred) or Redis, and the Perl
test harness:

```sh
cpan App::cpanminus
cpanm Test::Nginx
opm get ledgetech/lua-resty-http thibaultcha/lua-resty-mlcache fffonion/lua-resty-openssl
```

The datastore integration tests write fixture keys in database **9**, including
`d1:test.example.com`, `d2:test.example.com`, `c:1`, `p:100`, and `i:1000`.
Use a dedicated test Valkey or Redis instance. Tests default to `127.0.0.1:6379`; set
`REDIS_HOST` and `REDIS_PORT` to select another instance. The database number
is fixed by the fixtures.

With OpenResty's `nginx` on `PATH`, run:

```sh
make test
```

For an installation elsewhere:

```sh
make test OPENRESTY_PREFIX=/path/to/openresty
```

Alternatively, select the executable directly:

```sh
TEST_NGINX_BINARY=/path/to/openresty/nginx/sbin/nginx prove -r t
```

The HTTP test server and API fixtures default to unprivileged port **1984**.
TLS handshake tests use Unix sockets. Normal runs need no port configuration;
if 1984 is occupied, use one override for the listener and API fixtures:

```sh
TEST_NGINX_SERVER_PORT=19840 make test
```

`TEST_NGINX_PORT` is also supported as a fallback. Normally leave
`TEST_NGINX_CLIENT_PORT` unset so the harness client follows the server port.
Different port values alone do not guarantee that parallel runs are isolated:
they may still share Redis fixture keys and runtime paths.

For checkout paths containing spaces, the test helper automatically places
generated Nginx runtime files in a temporary directory. Certificate fixtures
are referenced using quoted absolute paths. An explicit `TEST_NGINX_SERVROOT`
overrides this choice; choose a short path without spaces. Temporary runtime
directories are retained for log inspection.

Run just the deterministic audit regressions, without a Redis server:

```sh
prove t/audit/01_regressions.t
```

Those cases run under OpenResty with injected backend and cache behavior. The
certificate-serving tests exercise actual TLS handshakes, Redis, and local API
fixtures. See [the test design notes](t/certificate_serving/README.md).

For isolated password, TLS, and client-certificate fixtures, install Python 3,
`openssl`, and a TLS-enabled `valkey-server`, then run:

```sh
make test-secure
make test-secure BACKEND=redis
```

Valkey is the default. The runner starts temporary datastore and Python API
servers and runs the entire suite against them. Ordinary `make test` skips the
fixture-dependent security cases. See [secure backend tests](t/security/README.md)
for prerequisites, focused runs, and CI coverage.

For linting and coverage:

```sh
luarocks install luacheck
luacheck lib --no-unused
make coverage
```

Coverage requires `luacov` to be installed and available to OpenResty. The CI
workflow also disables unused-variable warnings for linting.

# Versioning

This project uses Major.Minor.Patch semantic versioning.

Major.Minor version releases are pegged to the same Major.Minor releases as
`peter_sslers`.

For example:

| peter_sslers | lua-resty-peter_sslers | compatible ? |
| --- | --- | --- |
| 0.5.1 | 0.5.1 | YES |
| 0.5.1 | 0.5.0 | YES. Patch version mismatch ok! |
| 0.5.1 | 0.4.2 | NO. Minor version mismatch. |


# Author

Jonathan Vanasco <jonathan@findmeon.com>

Originally started in https://github.com/aptise/peter_sslers

The tests and github actions are copied or inspired by the excellent lua-resty-http
module https://github.com/ledgetech/lua-resty-http by James Hurst and the openresty
test suites.


# Licence

This module is licensed under the MIT License.  See `LICENSE.txt`
