# Secure backend tests

Run from the repository root. Requirements are OpenResty, `lua-resty-http`,
Test::Nginx, Python 3, the `openssl` command, and a TLS-enabled `valkey-server` or
`redis-server` executable on `PATH`. Use a modern OpenResty runtime supporting
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
modern OpenResty image. The older OpenResty matrix still exercises the ordinary
suite without requiring mTLS support.
