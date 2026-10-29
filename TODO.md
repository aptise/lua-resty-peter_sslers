* replace first-party nginx caching with lua-resty-mlcache
  * https://github.com/thibaultcha/lua-resty-mlcache


* some work could/should be done to make redis connections more performant
  * benchmark tests
  * ensure connections are performant
  * note: redis is a failover, so this is not high priority

* Extend the audit coverage beyond deterministic dependency injection.
  * exercise simultaneous autocert requests in multiple real workers
  * exercise autocert lease expiry, cache eviction, and flushes during provisioning
  * exercise shared-cache memory pressure with real certificate pairs
  * isolate Redis fixture keys so parallel runs cannot overwrite one another
  * handle bad resolvers

* Consider separate retry policies for malformed HTTP-200 API payloads and
  authoritative certificate misses; malformed 200 responses currently become
  negative cache entries.

* Consider explicit backend timeout settings and retry backoff for outages.

* Consider stronger certificate/key validation before clearing default TLS
  credentials, and tests for installation failures.
