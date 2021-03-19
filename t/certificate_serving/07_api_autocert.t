use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
$ENV{TEST_NGINX_RESOLVER} ||= '1.1.1.1';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_SERVER_SSL_PORT} ||= 12345;

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
# IMPORTANT
# On the tests where we EXPECT to serve the wrong certificate (fallback)
# DO NOT VERIFY THE CONNECTION
# e.g.
# 	- local sess, err = sock:sslhandshake(nil, "test.example.com", true)
# 	+ local sess, err = sock:sslhandshake(nil, "test.example.com", false)
#
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


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
        server_name example.com;  # fallback domain
        ssl_certificate_by_lua_block  {
            ngx.log(ngx.DEBUG, "server: ssl_certhandler")

            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"

            -- alias functions
            local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate
            
            -- nil to disable
            local redis_strategy = nil
			local fallback_server = 'http://127.0.0.1:1984/.well-known/admin'
			local enable_autocert = true
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
our $Config_exists = qq{
    lua_ssl_trusted_certificate ../../cert/_all.crt;
    server_tokens off;
	location "/.well-known/admin/api/domain/autocert.json" {
		# this will be called by the ssl server's `ssl_certificate_by_lua_block`
		content_by_lua_block {
			ngx.log(ngx.DEBUG, "server: api server")

            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"

			local f = assert(io.open("t/cert/test.example.com.crt", "r"))
			local cert = f:read("*all")
			f:close()           

			local f = assert(io.open("t/cert/test.example.com.key", "r"))
			local pkey = f:read("*all")
			f:close()           

			ngx.header.content_type = 'application/json'
			ngx.header["x-peter-sslers"] = ssl_certhandler._VERSION
			local json_string = '{"domain": ' ..
				'{"id": "1", "domain_name": "test.example.com", "is_active": true},' ..
				'"certificate_signed__latest_multi": ' ..
				'{"id": "9", "private_key": {"id": "9", "pem": "' .. pkey .. '"}, ' ..
				'"certificate": {"id": "9", "pem": "' .. cert ..'"}, "chain": {"id": "2",' ..
				'"pem": "' .. cert .. '"}, "fullchain": {"id": "9,2", "pem": "' .. cert .. '"}},' ..
				'"certificate_signed__latest_single": null, "result": "success", "notes": "existing certificate(s)"}'
			ngx.say(json_string)
		}
	}
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
our $Config_new = qq{
    lua_ssl_trusted_certificate ../../cert/_all.crt;
    server_tokens off;
	location "/.well-known/admin/api/domain/autocert.json" {
		# this will be called by the ssl server's `ssl_certificate_by_lua_block`
		content_by_lua_block {
			ngx.log(ngx.DEBUG, "server: api server")

            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"

			local f = assert(io.open("t/cert/test.example.com.crt", "r"))
			local cert = f:read("*all")
			f:close()           

			local f = assert(io.open("t/cert/test.example.com.key", "r"))
			local pkey = f:read("*all")
			f:close()           

			ngx.header.content_type = 'application/json'
			ngx.header["x-peter-sslers"] = ssl_certhandler._VERSION
			local json_string = '{"domain": ' ..
				'{"id": "1", "domain_name": "test.example.com", "is_active": true},' ..
				'"certificate_signed__latest_multi": ' ..
				'{"id": "9", "private_key": {"id": "9", "pem": "' .. pkey .. '"}, ' ..
				'"certificate": {"id": "9", "pem": "' .. cert ..'"}, "chain": {"id": "2",' ..
				'"pem": "' .. cert .. '"}, "fullchain": {"id": "9,2", "pem": "' .. cert .. '"}},' ..
				'"certificate_signed__latest_single": null, "result": "success", "notes": "new AcmeOrder, valid"}'
			ngx.say(json_string)
		}
	}
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
our $Config_new_fail_order = qq{
    lua_ssl_trusted_certificate ../../cert/_all.crt;
    server_tokens off;
	location "/.well-known/admin/api/domain/autocert.json" {
		# this will be called by the ssl server's `ssl_certificate_by_lua_block`
		content_by_lua_block {
			ngx.log(ngx.DEBUG, "server: api server")

            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"

			ngx.header.content_type = 'application/json'
			ngx.header["x-peter-sslers"] = ssl_certhandler._VERSION
			local json_string = '{"domain": null,"certificate_signed__latest_multi":null,' ..
				'"certificate_signed__latest_single":null,"AcmeOrder":{"id":1},"result":' ..
				'"error","notes":"new AcmeOrder, invalid"}'
			ngx.say(json_string)
		}
	}
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
                local sess, err = sock:sslhandshake(nil, "test.example.com", false)
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
our $Config_new_fail_get = qq{
    lua_ssl_trusted_certificate ../../cert/_all.crt;
    server_tokens off;
	location "/.well-known/admin/api/domain/autocert.json" {
		# this will be called by the ssl server's `ssl_certificate_by_lua_block`
		content_by_lua_block {
			ngx.log(ngx.DEBUG, "server: api server")

            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"

			ngx.header.content_type = 'application/json'
			ngx.header["x-peter-sslers"] = ssl_certhandler._VERSION
			
			-- curl http://127.0.0.1:7002/.well-known/admin/api/domain/autocert.json?openresty=1
			-- double escape, because this will be eval'd in Perl
			local json_string = '{"instructions": ["POST `domain_name` to automatically attempt a certificate provisioning", "curl --form \\'domain_name=example.com\\' http://127.0.0.1:7201/.well-known/admin/api/domain/autocert.json", "HTTP POST required", "IMPORTANT: No global AcmeAccount is configured yet."], "form_fields": {"domain_name": "required; a single domain name to process"}}'
			ngx.say(json_string)
		}
	}
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
                local sess, err = sock:sslhandshake(nil, "test.example.com", false)
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
our $Config_new_fail_post = qq{
    lua_ssl_trusted_certificate ../../cert/_all.crt;
    server_tokens off;
	location "/.well-known/admin/api/domain/autocert.json" {
		# this will be called by the ssl server's `ssl_certificate_by_lua_block`
		content_by_lua_block {
			ngx.log(ngx.DEBUG, "server: api server")

            -- requirements
            local ssl_certhandler = require "resty.peter_sslers"

			ngx.header.content_type = 'application/json'
			ngx.header["x-peter-sslers"] = ssl_certhandler._VERSION
			
			-- curl -F foo=bar http://127.0.0.1:7002/.well-known/admin/api/domain/autocert.json?openresty=1
			-- double escape, because this will be eval'd in Perl
			local json_string = '{"result": "error", "form_errors": {"domain_name": "Missing value", "Error_Main": "There was an error with your form."}, "domain": null, "certificate_signed__latest_single": null, "certificate_signed__latest_multi": null}'
			ngx.say(json_string)
		}
	}
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
                local sess, err = sock:sslhandshake(nil, "test.example.com", false)
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
=== TEST 1: API AutoCert - Domain Exists
--- http_config eval: $::HttpConfig
--- config eval: $::Config_exists
--- request
GET /t
--- response_body
connected: 1
SSL handshake OK!
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
server: ssl_certhandler
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
UpstreamAPI: autocert enabled
querying autocert API server at: http://127.0.0.1:1984/.well-known/admin/api/domain/autocert.json?openresty=1
API response HIT for : test.example.com
API response['result'] = success
API response['notes'] = existing certificate(s)
caching PEM cert & key into the shared cache : test.example.com
caching cert & key cdata into the worker : test.example.com
set ssl certificate : test.example.com
set ssl private key : test.example.com
--- no_error_log
Redis: lookup enabled
UpstreamAPI: lookup enabled
querying upstream API server at: http://127.0.0.1:1984/.well-known/admin/domain/test.example.com/config.json?openresty=1
query_api_upstream : test.example.com

=== TEST 2: API AutoCert - Domain New
--- http_config eval: $::HttpConfig
--- config eval: $::Config_new
--- request
GET /t
--- response_body
connected: 1
SSL handshake OK!
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
server: ssl_certhandler
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
UpstreamAPI: autocert enabled
querying autocert API server at: http://127.0.0.1:1984/.well-known/admin/api/domain/autocert.json?openresty=1
API response HIT for : test.example.com
API response['result'] = success
API response['notes'] = new AcmeOrder, valid
caching PEM cert & key into the shared cache : test.example.com
caching cert & key cdata into the worker : test.example.com
set ssl certificate : test.example.com
set ssl private key : test.example.com
--- no_error_log
Redis: lookup enabled
UpstreamAPI: lookup enabled
querying upstream API server at: http://127.0.0.1:1984/.well-known/admin/domain/test.example.com/config.json?openresty=1
query_api_upstream : test.example.com

=== TEST 3: API AutoCert - Domain New Fail Order
--- http_config eval: $::HttpConfig
--- config eval: $::Config_new_fail_order
--- request
GET /t
--- response_body
connected: 1
SSL handshake OK!
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
server: ssl_certhandler
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
UpstreamAPI: autocert enabled
querying autocert API server at: http://127.0.0.1:1984/.well-known/admin/api/domain/autocert.json?openresty=1
API response MISS for : test.example.com
failed to retrieve PEM for : test.example.com
unable to provide ssl for : test.example.com
--- no_error_log
Redis: lookup enabled
UpstreamAPI: lookup enabled
querying upstream API server at: http://127.0.0.1:1984/.well-known/admin/domain/test.example.com/config.json?openresty=1
query_api_upstream : test.example.com

=== TEST 4: API AutoCert - Domain New Fail - GET
--- http_config eval: $::HttpConfig
--- config eval: $::Config_new_fail_get
--- request
GET /t
--- response_body
connected: 1
SSL handshake OK!
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
server: ssl_certhandler
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
UpstreamAPI: autocert enabled
querying autocert API server at: http://127.0.0.1:1984/.well-known/admin/api/domain/autocert.json?openresty=1
API response MISS for : test.example.com
failed to retrieve PEM for : test.example.com
unable to provide ssl for : test.example.com
API response['instructions'] IS NOT NULL. ERROR
--- no_error_log
Redis: lookup enabled
UpstreamAPI: lookup enabled
querying upstream API server at: http://127.0.0.1:1984/.well-known/admin/domain/test.example.com/config.json?openresty=1
query_api_upstream : test.example.com
API response['form_errors'] IS NOT NULL. ERROR

=== TEST 5: API AutoCert - Domain New Fail - POST
--- http_config eval: $::HttpConfig
--- config eval: $::Config_new_fail_post
--- request
GET /t
--- response_body
connected: 1
SSL handshake OK!
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
server: ssl_certhandler
set_ssl_certificate
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
UpstreamAPI: autocert enabled
querying autocert API server at: http://127.0.0.1:1984/.well-known/admin/api/domain/autocert.json?openresty=1
API response MISS for : test.example.com
failed to retrieve PEM for : test.example.com
unable to provide ssl for : test.example.com
API response['form_errors'] IS NOT NULL. ERROR
--- no_error_log
Redis: lookup enabled
UpstreamAPI: lookup enabled
querying upstream API server at: http://127.0.0.1:1984/.well-known/admin/domain/test.example.com/config.json?openresty=1
query_api_upstream : test.example.com
API response['instructions'] IS NOT NULL. ERROR
