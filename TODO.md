* some work could/should be done to make redis connections more performant
  * benchmark tests
  * ensure connections are performant
  * note: redis is a failover, so this is not high priority

* Extend the audit coverage beyond deterministic dependency injection.
  * extend the existing real-worker lease tests to cache eviction and flushes during provisioning
  * exercise shared-cache memory pressure with real certificate pairs
  * isolate Redis fixture keys so parallel runs cannot overwrite one another
  * handle bad resolvers

* Consider retry backoff for outages. Backend timeouts are now configurable.

* Consider stronger certificate/key validation before clearing default TLS
  credentials, and tests for installation failures.
