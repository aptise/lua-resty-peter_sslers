# Secure backend tests

Run from the repository root. Requirements are OpenResty, `lua-resty-http`,
`lua-resty-mlcache`, `lua-resty-openssl`, Test::Nginx, Python 3, the `openssl`
command, and a TLS-enabled `valkey-server` or `redis-server` executable on `PATH`. Use a modern OpenResty runtime supporting
cosocket client certificates and `lua-resty-http >= 0.17.1` for the mTLS cases.

## Run the complete suite

```sh
make test-secure
make test-secure BACKEND=redis
```

Valkey is the default and preferred backend. The command starts isolated
plaintext, password-protected, TLS, and mTLS datastore servers, then runs the
whole test suite against them. Python HTTP/HTTPS servers independently enforce
Basic/Bearer authentication and, for mTLS, client certificates.

The runner generates a temporary CA and client/server certificates, selects
local ephemeral fixture ports, and removes the fixtures and stops its servers
when it exits. It does not require an existing Redis/Valkey service and replaces
`REDIS_HOST`/`REDIS_PORT` in the test environment with its isolated plaintext
instance. The harness HTTP port remains 1984 by default; override it if occupied:

```sh
TEST_NGINX_SERVER_PORT=19840 make test-secure
```

Use `OPENRESTY_PREFIX` with `make`, or `TEST_NGINX_BINARY` to select the executable.
The Nginx runtime-directory handling described in the
[test design notes](../certificate_serving/README.md) still applies.

## Run only security cases

```sh
python3 t/security/run.py
python3 t/security/run.py --backend redis
```

Both commands run just `t/security`; add `--full-suite` to include the existing
certificate-serving and audit cases. If Test::Nginx is installed from source in
a nonstandard Perl library directory, repeat `--prove-include` as needed:

```sh
TEST_NGINX_BINARY=/path/to/openresty/nginx/sbin/nginx \
    python3 t/security/run.py --prove-include /path/to/test-nginx/lib
```

`make test` and ordinary `prove -r t` run the option-validation cases but skip
the fixture-dependent connection cases unless the runner has set
`TEST_SECURITY_DIR`. Let the runner manage that variable and its temporary
files.

## Coverage

* `01_options.t` checks invalid options, incomplete or invalid PEM identities,
  header injection, authentication conflicts, unsupported clients, secret
  redaction, and safe TLS defaults using injected transport behavior.
* `02_connections.t` connects to the live fixtures. It tests both certificate
  storage layouts, password and ACL authentication, verified TLS, mTLS, Basic
  and Bearer API authentication, autocert form POSTs, rejected identities,
  secure connection reuse, credential changes, and database isolation.

The Python server returns the repository's test certificate payload in the
manager API format. It is a transport/authentication fixture, not a running
peter_sslers application. These cases supplement the existing TLS-handshake
integration tests; they do not replace them.

CI runs the complete fixture-backed suite separately for Valkey and Redis on a
modern OpenResty image. The ordinary-suite matrix covers OpenResty 1.29.2.4 and 1.31.1.1; the secure
backend job follows the 1.31 image series. CI uses LuaRocks 3.13.0 explicitly
to avoid the LuaJIT manifest constant-limit issue (LuaRocks #1797).

## Resolver and parallel-fixture audits

The runner also supplies a loopback UDP DNS fixture. Complete runs use it for
datastore resolver tests rather than a public DNS service. Focus the resolver
or cache-pressure cases with repeatable `--test` options:

```sh
python3 t/security/run.py --test t/network --test t/cache/02_pressure.t
```

`--test` and `--full-suite` are mutually exclusive. To verify concurrent TLS
fixture runs against the same datastore before running the suite:

```sh
python3 t/security/run.py --full-suite --parallel-fixtures 2
```

Each concurrent run has separate Nginx ports/runtime files and a random fixture
identity. The certificate-serving tests use run- and worker-specific SNI names
covered by the test wildcard certificate, preserving hostname verification.
Their datastore keys are removed and checked after lookup. Other datastore
fixtures and benchmarks also use random run identities plus worker IDs, so
identical PIDs in separate containers do not share keys.

After successful tests, the runner checks that its exclusive plaintext and
authenticated instances have no fixture keys left in databases 8 and 9. It
asserts cleanup rather than hiding leaks with a database flush. Secure CI runs
the parallel-fixture check for both backends.
