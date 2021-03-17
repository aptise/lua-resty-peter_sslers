use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
$ENV{TEST_NGINX_RESOLVER} = '8.8.8.8';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_SERVER_SSL_PORT} ||= 12345;

no_long_string();
#no_diff();

log_level("debug");
run_tests();

#
# these tests are kind of weird
# we set up two servers
# 1- a ssl server, which we want to test
# 2- a http server, which we can request against

# see https://github.com/openresty/lua-nginx-module/blob/master/t/139-ssl-cert-by.t
# see https://github.com/openresty/lua-nginx-module/blob/master/t/140-ssl-c-api.t


__DATA__
=== TEST 1: simple cert, one nginx server queries the other
--- http_config
    lua_package_path "$pwd/lib/?.lua;/usr/local/share/lua/5.1/?.lua;;";
    error_log logs/error.log debug;

	lua_shared_dict  cert_cache 100k;
	lua_code_cache  on;
	init_by_lua_block {
		require "resty.core"
		local ssl_certhandler = require "peter_sslers.ssl_certhandler"
		ssl_certhandler.initialize()
	}
	init_worker_by_lua_block {
		require "resty.core"
		local ssl_certhandler = require "peter_sslers.ssl_certhandler"
		-- cert_cache_duration, lru_cache_duration, lru_maxitems
		ssl_certhandler.initialize_worker(600, 60, 200)
	}
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name test.com;
		ssl_certificate_by_lua_block  {
			collectgarbage()

            ngx.log(ngx.ERR, "server: ssl_certhandler")

			-- requirements
			local ssl_certhandler = require "peter_sslers.ssl_certhandler"

			-- alias functions
			local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate

			-- nil to disable
			local redis_strategy = nil
			local fallback_server = nil
			local enable_autocert = nil
			ssl_certhandler_set(redis_strategy, fallback_server, enable_autocert)
		}
		ssl_certificate ../../cert/test2.crt;
		ssl_certificate_key ../../cert/test2.key;
        server_tokens off;
        location /foo {
            default_type 'text/plain';
            content_by_lua_block { ngx.status = 201 ngx.say("foo") ngx.exit(201) }
            more_clear_headers Date;
        }
	}
--- config
    lua_ssl_trusted_certificate ../../cert/test.crt;

	server_tokens off;
	location /t {
        content_by_lua_block {
            ngx.log(ngx.ERR, "server: test server")

            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end
            end  -- do
            -- collectgarbage()
		}
	}
--- request
GET /t
--- response_body
connected: 1
failed to do SSL handshake: 18: self signed certificate
--- error_log
[notice]
ssl_certhandler.initialize
ssl_certhandler.initialize_worker
[debug]
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : test.com
ssl_certhandler_set(): SNI Lookup for : test.com
ssl_certhandler_set(): shared `cert_cache` MISS for : test.com
ssl_certhandler_set(): failed to retrieve PEM for : test.com
