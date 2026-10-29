use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
$ENV{TEST_NGINX_RESOLVER} ||= '1.1.1.1';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

$ENV{REDIS_HOST} ||= "127.0.0.1";
$ENV{REDIS_PORT} ||= "6379";

our $HttpConfig_1 = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    error_log logs/error.log debug;
    lua_shared_dict  cert_cache 100k;
    lua_shared_dict cert_cache_ipc 100k;
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

            local serve = assert(loadfile("$pwd/t/lib/datastore_fixture.lua"))()
            serve(1, "$ENV{REDIS_HOST}", "$ENV{REDIS_PORT}")
        }
        ssl_certificate "$pwd/t/cert/example.com.crt";  # fallback cert
        ssl_certificate_key "$pwd/t/cert/example.com.key";  # fallback key
        server_tokens off;
        location /actual-test {
            default_type 'text/plain';
            content_by_lua_block { ngx.status = 201 ngx.say("actual-test") ngx.exit(201) }
            more_clear_headers Date;
        }
    }
};
our $Config = qq{
    lua_ssl_trusted_certificate "$pwd/t/cert/_all.crt";
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
                local sess, err = sock:sslhandshake(nil, "prime1-$ENV{TEST_NGINX_FIXTURE_ID}-" .. ngx.worker.pid() .. ".test.example.com", true)
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
--- error_log eval
[
    qr{\[notice\]},
    qr{peter_sslers\.initialize},
    qr{peter_sslers\.initialize_worker},
    qr{\[debug\]},
    qr{Redis:\ changing\ to\ db:9,\ times:0},
    qr{set_ssl_certificate},
    qr{set_ssl_certificate\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{SNI\ Lookup\ for\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{cert_lrucache\ MISS\ for\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{shared\ `cert_cache`\ MISS\ for\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{Redis:\ lookup\ enabled},
    qr{Redis:\ prime_1__query_redis\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{caching\ PEM\ cert\ \&\ key\ into\ the\ shared\ cache\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{can\ provide\ ssl\ for\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{caching\ cert\ \&\ key\ cdata\ into\ the\ worker\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{set\ ssl\ certificate\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
    qr{set\ ssl\ private\ key\ :\ prime1-[a-z0-9-]+-\d+\.test\.example\.com},
]
--- no_error_log
Redis: invalid `redis_strategy` not (1, 2) is `
Redis: could not get connection
failed to set ssl certificate :
failed to set ssl private key :
