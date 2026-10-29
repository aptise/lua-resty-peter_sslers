# Valkey, Redis, and secure API connections

Valkey is the preferred datastore backend. Redis remains supported through the
same `lua-resty-redis` protocol client. Both use the existing prime-1 and prime-2
certificate layouts; there is no separate Valkey strategy or migration format.
The public `redis_strategy` argument still selects layout `1` or `2`, and `nil`
disables datastore lookups.

The connection options, `valkey_update_defaults` alias, and `api_update_defaults`
were added in 1.0.0. See the [Lua API reference](api.md) for phases and return
values.

## Configuration entry points

Call these functions in `init_worker_by_lua_block`, after loading the module:

```lua
local handler = require 'resty.peter_sslers'
handler.initialize_worker(600, 60, 200)
handler.valkey_update_defaults(host, port, database, options)
handler.api_update_defaults(api_options)
```

`valkey_update_defaults` and `redis_update_defaults` are aliases for the same
function and update the same settings. The existing three-argument Redis call
remains supported. Omitting its fourth argument preserves previously configured
connection options; passing `{}` resets those options to their defaults.
`api_update_defaults` takes a complete options table; `{}` clears its previous
authentication and client-certificate settings.

Options are copied. Client certificate PEM is parsed when configuring the
worker. Mutating the original table afterward does not update the active
configuration. Reconfigure explicitly when rotating credentials. Avoid calling
these setters on every handshake: each supplied options table creates a new
connection-pool configuration.

The datastore defaults remain `127.0.0.1:6379`, database `9`, with plaintext
connections and no authentication. API transport follows the `fallback_server`
URL: use `https://` for TLS. Setting authentication does not enable encryption.

## Options

| Option | Valkey/Redis | Python API | Default and behavior |
| --- | --- | --- | --- |
| `username` | ACL username for `AUTH username password` | HTTP Basic username | Unset. Requires `password` when supplied. |
| `password` | `AUTH password`, or ACL password with `username` | HTTP Basic password | Unset. API password without a username uses an empty username. |
| `authorization` | Unsupported | Complete HTTP Authorization header, e.g. `Bearer …` | Unset. Mutually exclusive with Basic credentials; line breaks are rejected. |
| `ssl` | Enables TLS when `true` | Unsupported; use an HTTPS URL | Unset/disabled for the datastore. |
| `ssl_verify` | Verifies the server certificate | Verifies the HTTPS server certificate | `true`. Configure trusted CAs in Nginx. `false` explicitly disables verification. |
| `server_name` | TLS SNI and verification name | TLS SNI and verification name | Datastore host, or API URL host, respectively. Override when connecting by IP to a named server. |
| `client_cert` | Client certificate chain in PEM format | Client certificate chain in PEM format | Unset. PEM contents, not a filename. Requires `client_key`. |
| `client_key` | Client private key in PEM format | Client private key in PEM format | Unset. Requires `client_cert`. |
| `timeout` | Socket timeout in milliseconds | Socket timeout in milliseconds | Unset; inherits client/Nginx defaults. Must be positive when supplied. |
| `retry_backoff` | Datastore lookup cooldown in seconds | API lookup cooldown in seconds | `1`. Accepts numbers from `0` through `60`, including fractional seconds; `0` disables cooldowns. |

Unknown options and invalid values raise configuration errors. Datastore
client certificates require `ssl = true`; API client certificates require an
HTTPS URL. Client certificates and passwords can be combined. A server may
require both transport-level certificate authentication and application-level
credentials.

For the API, Basic or Bearer authorization applies to both ordinary GET lookups
and autocert POST requests. Keep credentials in the options table rather than
embedding them in the URL, because request URLs appear in debug logs.

## Retry cooldowns

`set_ssl_certificate` applies a fixed cooldown after a failed backend lookup.
The default is one second for each backend, including configurations that omit
an options table. Set `retry_backoff` separately in the datastore and API options
to change it. This value is in seconds; `timeout` is in milliseconds. It is a
fixed delay, not exponential backoff.

Cooldown markers are shared across workers in `cert_cache` and are separate
from certificate entries and negative caching. During a cooldown, a cache miss
skips that backend without waiting. Cached certificates remain available, and a
datastore cooldown still permits API fallback. If no usable certificate is
found, the configured default certificate remains in place. Cooldowns also
apply to API autocert requests.

Datastore connection, authentication, and transport failures cool down the
configured datastore. API transport failures, request exceptions, and HTTP
401, 403, 429, or numeric statuses >= 500 cool down the configured API. Invalid
PEM, mismatched certificate/key pairs, malformed domain payloads, and datastore
record/command errors cool down only the affected domain on that backend. Other unsuccessful API statuses except
404 also receive a domain cooldown. Clean datastore misses, HTTP 404, and
explicit API certificate absence retain the existing absence-caching behavior
and do not start a cooldown.

After expiry, the next cache miss can try again. A successful in-flight lookup
clears the corresponding cooldown; failures arriving during an existing
cooldown do not extend it. Requests already in flight may still complete, so
this is not a limit of one concurrent request per backend. Markers use
`safe_add`, which avoids evicting cached certificates; if shared memory is full,
a cooldown may not be stored and later requests can retry immediately.

Cooldown identities include the endpoint and connection options, allowing
workers with the same configuration to share them. Changing credentials or
connection settings uses a different identity; credentials are hashed rather
than stored in dictionary keys. Configuration changes do not flush cached
certificates. The low-level connection and query helpers remain direct calls
and do not enforce these cooldowns.

For example, merge these fields into your existing initialization options:

```lua
handler.valkey_update_defaults(host, port, database, {
    retry_backoff = 0.5,
    -- Include any existing authentication and TLS options here.
})
handler.api_update_defaults({
    retry_backoff = 2,
    -- Include any existing authentication and TLS options here.
})
```

Supplying an options table replaces the previous options, so retain your
credentials and TLS settings when changing the cooldown. Use `retry_backoff = 0`
to restore immediate retries for a backend.

## Trust and client certificates

Configure `lua_ssl_trusted_certificate` with a PEM bundle containing the CAs
that issued the datastore and API server certificates. The directive governs
both outgoing clients; there is no per-backend CA-file option. Set
`lua_ssl_verify_depth` to suit the certificate chains.

`server_name` changes the TLS identity, not the HTTP `Host` header. Use the
required virtual-host name in the API URL when HTTP routing depends on it;
configure an Nginx `resolver` for hostnames that need cosocket DNS resolution.

Load client certificate and private-key files into PEM strings in each worker.
Those files must be readable by the Nginx worker user. Server trust certificates
and client identity certificates serve different purposes: configuring the CA
bundle alone does not send a client certificate.

The following example combines ACL/password authentication, verified TLS, and
separate client identities for the two backends. Replace the paths, names,
ports, and usernames for your deployment. Supply the passwords in the Nginx
process environment before startup.

```nginx
env VALKEY_PASSWORD;
env PETER_SSLERS_API_PASSWORD;

http {
    lua_shared_dict cert_cache 1m;
    lua_shared_dict cert_cache_ipc 100k;
    lua_ssl_trusted_certificate /etc/nginx/backend-cas.pem;
    lua_ssl_verify_depth 3;

    init_by_lua_block {
        require 'resty.core'
        require('resty.peter_sslers').initialize()
    }
    init_worker_by_lua_block {
        local function read_pem(path)
            local file = assert(io.open(path, 'r'))
            local pem = assert(file:read('*a'))
            file:close()
            return pem
        end
        local handler = require 'resty.peter_sslers'
        handler.initialize_worker(600, 60, 200)
        handler.valkey_update_defaults('127.0.0.1', 6380, 9, {
            username = 'certificate-reader',
            password = assert(os.getenv('VALKEY_PASSWORD')),
            ssl = true,
            server_name = 'valkey.internal',
            client_cert = read_pem('/etc/nginx/valkey-client.crt'),
            client_key = read_pem('/etc/nginx/valkey-client.key'),
            timeout = 2000,
        })
        handler.api_update_defaults({
            username = 'certificate-reader',
            password = assert(os.getenv('PETER_SSLERS_API_PASSWORD')),
            server_name = 'cert-manager.internal',
            client_cert = read_pem('/etc/nginx/api-client.crt'),
            client_key = read_pem('/etc/nginx/api-client.key'),
            timeout = 2000,
        })
    }

    server {
        listen 443 ssl;
        server_name example.com;
        ssl_certificate /etc/nginx/default/fullchain.pem;
        ssl_certificate_key /etc/nginx/default/privkey.pem;
        ssl_certificate_by_lua_block {
            require('resty.peter_sslers').set_ssl_certificate(
                1, 'https://127.0.0.1:6543/.well-known/admin', nil)
        }
    }
}
```

For password-only datastore authentication, omit `username`. For certificate-only
connections, omit application credentials where the server permits it. To use
Bearer authentication for the API, replace its `username` and `password` fields
with `authorization = 'Bearer ' .. token`, retaining any TLS and client-certificate
fields you need.

## Compatibility and pooling

| Capability | Requirement |
| --- | --- |
| Datastore TLS | `lua-resty-redis >= 0.28` and an SSL-enabled OpenResty build. Older clients are rejected when TLS is requested. |
| Datastore mTLS | Datastore TLS support plus the OpenResty cosocket `setclientcert` API. Missing support is rejected before connecting. |
| API mTLS | `lua-resty-http >= 0.17.1` plus a cosocket supporting `setclientcert`. Unsupported configurations return a failed lookup. |

Datastore client certificates use the Redis client's underlying `_sock`, because
it does not expose a public certificate setter. That access is guarded and
covered by compatibility tests. An incompatible client fails explicitly rather
than silently omitting the requested client identity.

Datastore pools are separated by endpoint, database, and connection-options
revision. API pools are separated by configured backend URL and options
revision. Reconfiguring credentials or TLS options therefore avoids reusing
connections authenticated with the previous identity. Existing idle connections
remain subject to their keepalive expiry.

Changing connection settings does not flush certificate caches. Entries remain
until expiry or explicit invalidation; administration expiration broadcasts L1
invalidation through mlcache IPC.

## Verification

See [secure test instructions](../t/security/README.md). The fixtures test live
Valkey/Redis connections and authenticated Python HTTP/HTTPS servers, including
rejection of incorrect credentials, untrusted servers, wrong hostnames, missing
client certificates, and connection-pool identity changes. Existing tests also
exercise the certificate-serving handshake path.
