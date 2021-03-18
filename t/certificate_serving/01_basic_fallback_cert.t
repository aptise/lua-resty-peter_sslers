use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
$ENV{TEST_NGINX_RESOLVER} = '1.1.1.1';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_SERVER_SSL_PORT} ||= 12345;
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    error_log logs/error.log debug;
	lua_shared_dict  cert_cache 100k;
	lua_code_cache  on;
	init_by_lua_block {
		require "resty.core"
        local ssl_certhandler = require "resty.peter_sslers"
		ssl_certhandler.initialize()
	}
	init_worker_by_lua_block {
		require "resty.core"
        local ssl_certhandler = require "resty.peter_sslers"
		-- cert_cache_duration, lru_cache_duration, lru_maxitems
		ssl_certhandler.initialize_worker(600, 60, 200)
	}
    server {
        listen unix:$ENV{TEST_NGINX_HTML_DIR}/nginx.sock ssl;
        server_name example.com;
		ssl_certificate_by_lua_block  {
            ngx.log(ngx.ERR, "server: ssl_certhandler")

			-- requirements
			local ssl_certhandler = require "resty.peter_sslers"

			-- alias functions
			local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate

			-- nil to disable
			local redis_strategy = nil
			local fallback_server = nil
			local enable_autocert = nil
			ssl_certhandler_set(redis_strategy, fallback_server, enable_autocert)
		}
		ssl_certificate ../../cert/example.com.crt;
		ssl_certificate_key ../../cert/example.com.key;
        server_tokens off;
        location /actual-test {
            default_type 'text/plain';
            content_by_lua_block { ngx.status = 201 ngx.say("actual-test") ngx.exit(201) }
            more_clear_headers Date;
        }
	}
};
our $Config = qq{
    lua_ssl_trusted_certificate ../../cert/example.com.crt;
	server_tokens off;
	location /t {
        content_by_lua_block {
            ngx.log(ngx.ERR, "server: test server")
            do
                local sock = ngx.socket.tcp()
                sock:settimeout(2000)
                local ok, err = sock:connect("unix:$ENV{TEST_NGINX_HTML_DIR}/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end
                ngx.say("connected: ", ok)
                local sess, err = sock:sslhandshake(nil, "example.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end
                ngx.say("SSL handshake OK!")
            end  -- do
            -- collectgarbage()
		}
	}
};
no_long_string();
#no_diff();
log_level("debug");
run_tests();

__DATA__
=== TEST 1: simple cert, one nginx server queries the other
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
GET /t
--- response_body
connected: 1
SSL handshake OK!
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
[debug]
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : example.com
ssl_certhandler_set(): SNI Lookup for : example.com
ssl_certhandler_set(): shared `cert_cache` MISS for : example.com
ssl_certhandler_set(): failed to retrieve PEM for : example.com
--- no_error_log
cert_lrucache HIT for : example.com
shared `cert_cache` HIT for : example.com
failed to set ssl private key : example.com
set ssl private key : example.com
