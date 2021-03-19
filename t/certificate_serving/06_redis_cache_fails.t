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

# also
# we may end up with a redcon, but invald
# if that is the case, the response is
# 	xx Redis: failed to connect to redis: 
# 	++ Redis: failed to detect times:

our $HttpConfig_GoodIp_BadRedisPort = qq{
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
            -- set redis to fail! we want a broken connection
            -- test a broken port
            ssl_certhandler.redis_update_defaults("127.0.0.1", "1", 9)

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
our $HttpConfig_BadRedisHostname = qq{
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
            -- set redis to fail! we want a broken connection
            -- test a broken port
            ssl_certhandler.redis_update_defaults("nxdomain.example.com", "1", 9)

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
=== TEST 1: Good IP, Bad Port
--- http_config eval: $::HttpConfig_GoodIp_BadRedisPort
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
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
Redis: lookup enabled
Redis: about to connect to redis: 127.0.0.1:1
Redis: failed to detect times:
Redis: could not get connection
failed to retrieve PEM for : test.example.com
unable to provide ssl for : test.example.com

=== TEST 2: Bad Hostname
--- http_config eval: $::HttpConfig_BadRedisHostname
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
ssl_certhandler_set(): set_ssl_certificate : test.example.com
ssl_certhandler_set(): SNI Lookup for : test.example.com
cert_lrucache MISS for : test.example.com
shared `cert_cache` MISS for : test.example.com
Redis: lookup enabled
Redis: about to connect to redis: nxdomain.example.com
Redis: failed to detect times:
Redis: could not get connection
failed to retrieve PEM for : test.example.com
unable to provide ssl for : test.example.com


