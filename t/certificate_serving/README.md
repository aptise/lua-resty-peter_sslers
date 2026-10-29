It took a bit of work figuring out how OpenResty tests these scenarios, so I am
documenting it here:

# See Also

Relevant upstream (OpenResty) tests

* https://github.com/openresty/lua-nginx-module/blob/master/t/139-ssl-cert-by.t
* https://github.com/openresty/lua-nginx-module/blob/master/t/140-ssl-c-api.t

# Perl "Gotcha"

This took the longest to figure out, because I haven't used Perl in 15+ years
and the error messages can be confusing.

The shared configuration strings use Perl `qq{...}`, which interpolates `$pwd`
and environment variables when the string is constructed. The block directive
then evaluates a Perl expression to retrieve that shared string:

```perl
--- http_config eval: $::HttpConfig
```

Package variables referenced from block expressions use the `::` qualifier.
API-related `error_log eval` blocks also use `qq{...}` so expected URLs follow
`TEST_NGINX_SERVER_PORT`.

# Running the tests

Run from the repository root with OpenResty's `nginx` on `PATH`:

```sh
make test
TEST_NGINX_SERVER_PORT=19840 make test
```

The default HTTP port is 1984. `TEST_NGINX_SERVER_PORT` controls both the harness
listener and the local API URLs; normally leave `TEST_NGINX_CLIENT_PORT` unset.
The TLS server uses a Unix socket, so there is no separate TLS port to configure.

`t/lib/PeterSSLers/TestConfig.pm` loads before Test::Nginx in each test file.
It selects the shared port and, when the checkout path contains whitespace,
places generated runtime files in a temporary directory. Runtime directories
are retained so failed runs can be inspected. Certificate paths are absolute
and quoted. An explicit `TEST_NGINX_SERVROOT` takes precedence and should be a
short path without whitespace.

The prime-1, prime-2, and command-error integration cases require Valkey or Redis
and write fixture data in database 9. Use a dedicated test instance; `REDIS_HOST` and `REDIS_PORT`
override the default `127.0.0.1:6379`. Using different HTTP ports does not isolate
Redis fixtures between concurrent runs.

The cases in `t/audit/01_regressions.t` use injected dependencies from
`t/audit/regressions.lua` to test backend errors and cache behavior without a
Redis server. They still require OpenResty and Test::Nginx. Mocked parsing does
not replace the real TLS handshake coverage in this directory.

`t/audit/02_api_responses.t` uses the real JSON decoder and Nginx logger with an
injected HTTP transport. `03_autocert_workers.t` uses two distinct worker
processes, real shared dictionaries, real PEM parsing, and worker LRUs to check
pending requests and stale autocert leases; HTTP transport and TLS-phase setters
are injected. `04_redis_errors.t` injects datastore failures without a live
service. `08_redis_command_errors.t` in this directory checks actual wrong-type
responses with per-worker fixture keys and cleanup.

For live password, TLS, and mTLS tests against both datastores and Python API
fixtures, use `make test-secure` (Valkey) or `make test-secure BACKEND=redis`.
See [secure backend tests](../security/README.md) for setup and coverage.

# Test Design

The goal of the tests is to verify certificate selection during a TLS
handshake. These cases use a Lua cosocket client inside Nginx to perform that
handshake while Test::Nginx drives an HTTP request.

The workaround is to define two servers within nginx:

* Server A 
  * HTTPS
  * SSL Server routines you want to test in `/actual-test`
  * defined in `http_config`

* Server B
  * HTTP
  * actually queried by the Test::Nginx file
  * defined in `config`
  * `location /t` contains a `content_by_lua_block`, which is used to connect
    to Server A, and performs a TLS handshake

The flow looks like this:

* User requests http://B/t
* B/t opens a TLS connection to A with the requested SNI name


Both nginx servers will share the same log, so the `error_log` tests should be
written to reflect that.  However, the `response_body` test will only check the
"Server B" response.  The handshake result for "Server A" is checked within the Lua
block in "Server B"; the handshake alone does not issue an HTTP request.

In the case of Test 5 "API Fallback", two servers run 3 routes(!)

* Server A 
  * HTTPS
  * SSL Server routines you want to test in `/actual-test`
  * defined in `http_config`

* Server B
  * HTTP
  * actually queried by the Test::Nginx file
  * defined in `config`
  * `location /t` contains a `content_by_lua_block`, which is used to connect
    to Server A, and performs a TLS handshake
  * `location /.well-known/admin/domain/test.example.com/config.json` contains a 
    `content_by_lua_block`, which is queried during the Server A TLS handshake
    to mimic the upstream Pyramid application
    
The flow looks like this:

* User requests http://B/t
* B/t opens a TLS connection to A with the requested SNI name
* During the TLS handshake with A, a query is sent to
  http://B/.well-known/admin/domain/test.example.com/config.json    
    

# Certificate/key validation and installation failures

`t/audit/05_installation.t` uses real PEM parsing and OpenSSL key matching with
controlled TLS setters. It covers mismatched keys (including a key belonging to
a later certificate in a chain), malformed PEM, shared-cache rejection,
datastore-to-API fallback, and stopping at each failed installation step. A
worker LRU hit must reuse the validated pair without another key-match check.

`09_validation.t` performs actual verified TLS handshakes over a Unix socket.
Mismatched backend and legacy shared-cache pairs must preserve the configured
default certificate. A valid dynamic pair must serve successfully. Injected
clear, certificate-set, and key-set failures must abort the handshake and stop
further installation calls. These cases require `lua-resty-openssl` and run
without a datastore service; the full Valkey and Redis fixture runs include them.
