use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
$ENV{TEST_NGINX_RESOLVER} ||= '1.1.1.1';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_SERVER_SSL_PORT} ||= 12345;

$ENV{REDIS_HOST} ||= "127.0.0.1";
$ENV{REDIS_PORT} ||= "6379";

our $HttpConfig_1 = qq{
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
        server_name example.com;  # fallback domain
        resolver $ENV{TEST_NGINX_RESOLVER};
        ssl_certificate_by_lua_block  {
            ngx.log(ngx.DEBUG, "server: ssl_certhandler")

            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"
            ssl_certhandler.redis_update_defaults("$ENV{REDIS_HOST}", "$ENV{REDIS_PORT}", 9)

			-- PRIME START
			-- load the cert into the Redis cache
            ngx.log(ngx.DEBUG, "PRIME REDIS 1 | START")
			local certificate_pem = ssl_certhandler.certificate_pairing()
			local f = assert(io.open("t/cert/test.example.com.crt", "r"))
			certificate_pem['cert'] = f:read("*all")
			f:close()           
			local f = assert(io.open("t/cert/test.example.com.key", "r"))
			certificate_pem['pkey'] = f:read("*all")
			f:close()           

			-- use the packages redis connection
			local redcon = ssl_certhandler.get_redcon()

			-- 1. prime domain
			-- prime domain: A- core entry
			local key = "d1:test.example.com"
			local val = {}
			 -- certificate id
			 val["c"] = 1
			 -- pkey id
			 val["p"] = 100
			 -- chain id
			 val["i"] = 1000
			local res, err = redcon:hmset(key, val)
			if not res then
	            ngx.log(ngx.ERR, "failed to set DOMAIN: ", err)
				ngx.say("failed to set DOMAIN: ", err)
				return
			end
			-- prime domain: B- cert
			-- certificate id
			local key = "c:1"
			local res, err = redcon:set(key, certificate_pem['cert'])
			if not res then
	            ngx.log(ngx.ERR, "failed to set CERTFICATE: ", err)
				ngx.say("failed to set CERTIFICATE: ", err)
				return
			end
			-- 2. prime pkey
			-- pkey id
			local key = "p:100"
			local res, err = redcon:set(key, certificate_pem['pkey'])
			if not res then
	            ngx.log(ngx.ERR, "failed to set PKEY: ", err)
				ngx.say("failed to set PKEY: ", err)
				return
			end
			-- 3. prime chain
			-- chain id
			local key = "i:1000"
			local res, err = redcon:set(key, certificate_pem['cert'])
			if not res then
	            ngx.log(ngx.ERR, "failed to set CHAIN: ", err)
				ngx.say("failed to set CHAIN: ", err)
				return
			end
            ngx.log(ngx.DEBUG, "PRIME REDIS 1 | END")
			-- PRIME END
		
            -- alias functions
            local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate
            
            -- nil to disable
            local redis_strategy = 1
            local fallback_server = nil
            local enable_autocert = nil
            ssl_certhandler_set(redis_strategy, fallback_server, enable_autocert)
        }
        ssl_certificate ../../cert/example.com.crt;  # fallback cert
        ssl_certificate_key ../../cert/example.com.key;  # fallback key
        server_tokens off;
        location /actual-test {
            default_type 'text/plain';
            content_by_lua_block { ngx.status = 201 ngx.say("actual-test") ngx.exit(201) }
            more_clear_headers Date;
        }
    }
};
our $Config = qq{
    lua_ssl_trusted_certificate ../../cert/_all.crt;
    server_tokens off;
    location /t {
        content_by_lua_block {
            ngx.log(ngx.DEBUG, "server: test server")
            do
                local sock = ngx.socket.tcp()
                sock:settimeout(2000)
                local ok, err = sock:connect("unix:$ENV{TEST_NGINX_HTML_DIR}/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end
                ngx.say("connected: ", ok)
                local sess, err = sock:sslhandshake(nil, "test.example.com", true)
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
=== TEST 1: preload the cert into redis, prime 1
--- http_config eval: $::HttpConfig_1
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
Redis: changing to db:9, times:0
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
Redis: lookup enabled
Redis: prime_1__query_redis : test.example.com
caching PEM cert & key into the shared cache : test.example.com
can provide ssl for : test.example.com
caching cert & key cdata into the worker : test.example.com
set ssl certificate : test.example.com
set ssl private key : test.example.com
--- no_error_log
Redis: invalid `redis_strategy` not (1, 2) is `
Redis: could not get connection
failed to set ssl certificate : test.example.com
failed to set ssl private key : test.example.com
