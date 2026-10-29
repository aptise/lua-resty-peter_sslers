# Datastore connection and lookup benchmarks

These development benchmarks remain separate from correctness tests and have
no timing pass/fail thresholds. They start a temporary Valkey server by default,
prepare certificate fixtures in database 9, measure real OpenResty cosocket
operations, clean up the keys, and stop the server afterward. No existing
Valkey/Redis instance is used.

Requirements: Python 3, a `valkey-server` or `redis-server` executable, and the
OpenResty `resty` CLI on `PATH`, with the package's `lua-resty-http`,
`lua-resty-mlcache`, and `lua-resty-openssl` dependencies installed. The high-resolution monotonic clock
supports Linux and macOS.

From the repository root:

```sh
make benchmark
make benchmark BACKEND=redis BENCHMARK_ITERATIONS=2000
python3 benchmarks/run.py --iterations 2000 --output /tmp/valkey-benchmark.json
python3 benchmarks/run.py --backend redis --output /tmp/redis-benchmark.json
```

To compare runtime or server versions explicitly:

```sh
python3 benchmarks/run.py --resty /path/to/openresty/bin/resty \
    --server-binary /path/to/valkey-server --output /tmp/version-comparison.json
```

`RESTY_BINARY` can also select the CLI. `--iterations` counts measured lookups
per query/connection combination, after warming the JIT and pool. The script
checks every returned certificate and key. Pooled runs must reuse connections;
fresh runs drain the pool first and must create a new connection on every
iteration. Failures of those checks fail the benchmark.

## Workloads and output

The retained references do not call production query functions:

* `serial_reference`: HMGET for prime-1 IDs, then three sequential GETs.
* `pipeline_reference`: HMGET for IDs, then the same three GETs in one pipeline.
* `current_prime1`: the package's current prime-1 implementation.
* `current_prime2`: the package's current prime-2 implementation, a single HMGET.

Every workload returns the same full chain and private key. Each is measured
with pooled and fresh connections. The optimized prime-1 path preserves GET
commands and their individual errors, avoiding a new MGET ACL requirement.
Pipelining reduces its query round trips from four to two without changing the
number of datastore commands or the stored certificate layout.

JSON output includes median and p95 lookup times in microseconds, elapsed
milliseconds, operations per second, new/reused connection counts, server and
OpenResty versions, platform, payload sizes, clock type, and a hash of the
production library source. Save output files with the revision being evaluated
when comparing future implementations. The baseline functions stay available
even if production changes again.

These are plaintext loopback measurements from one sequential client. They
bypass the worker/shared certificate caches and API fallback, so they measure
datastore fallback costs rather than warm TLS-handshake throughput. They do not
measure concurrent load, TLS/mTLS overhead, WAN latency, or production tail
latency. Run benchmarks one at a time, repeat measurements on an otherwise idle
host, and compare like environments. Block order and host scheduling can affect
results; a single run is not a production performance guarantee.
