It took a bit of work figuring out how OpenResty tests these scenarios, so I am
documenting it here:

# See Also

Relevant upstream (OpenResty) tests

* https://github.com/openresty/lua-nginx-module/blob/master/t/139-ssl-cert-by.t
* https://github.com/openresty/lua-nginx-module/blob/master/t/140-ssl-c-api.t

# Perl "Gotcha"

This took the longest to figure out, because I haven't used Perl in 15+ years
and the error messages can be confusing.

The `$pwd` element is not interpolated into the shared `$HttpConfig` variable
when defined.  Instead, one must use `eval`

    --- http_config eval: $::HttpConfig

# Test Design

The goal of the tests is to query an SSL server. The OpenResty test framework,
Test::Nginx, does not make this directly possible.

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
    to Server A, and issues a request against `actual-test`

Both nginx servers will share the same log, so the `error_log` tests should be
written to reflect that.  However, the `response_body` test will only check the
"Server B" response.  The response for "Server A" can be checked within the Lua
block in "Server B".
