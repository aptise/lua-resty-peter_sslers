* replace first-party nginx caching with lua-resty-mlcache
  * https://github.com/thibaultcha/lua-resty-mlcache


* some work could/should be done to make redis connections more performant
  * benchmark tests
  * ensure connections are performant
  * note: redis is a failover, so this is not high priority

* The tests for certificate serving need to be improved.
  * expand the test suite to query
    * autocert blocking
  * handle bad resolvers