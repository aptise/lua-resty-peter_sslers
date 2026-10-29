# Resolver failure coverage

Use the isolated fixture runner:

```sh
python3 t/security/run.py --test t/network
```

The local UDP DNS fixture returns NXDOMAIN and SERVFAIL, drops packets, sends
truncated replies, and allows a failed hostname to recover. Tests also cover
missing Nginx resolver configuration and datastore DNS failure followed by a
successful API fallback. Requests are counted by the fixture to verify that the
intended DNS path was exercised. No public DNS service is needed.

The tests use real DNS, HTTP/datastore clients, PEM parsing, and mlcache. TLS
phase accessors and setters are injected so lookup can be driven from an HTTP
request; separate certificate-serving and memory-pressure cases perform actual
verified TLS handshakes.

The runner selects a local DNS port and provides it through its generated
`ports.json`. Nginx uses a bounded resolver timeout. The recovery test waits for
the resolver's one-second negative TTL, then verifies that certificate-level
negative caching does not suppress a successful retry.

Ordinary `prove -r t` skips these cases unless the runner supplies its fixtures.
The complete secure CI runs include them for both Valkey and Redis.
