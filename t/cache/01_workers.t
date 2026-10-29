use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
our $pwd = cwd();
sub cache_config {
    my ($scenario) = @_;
    return qq{
        lua_package_path "$pwd/lib/?.lua;;";
        lua_shared_dict cert_cache 1m;
        lua_shared_dict cert_cache_ipc 100k;
        lua_shared_dict cache_control 100k;
        init_worker_by_lua_block {
            assert(loadfile("$pwd/t/cache/workers.lua"))()("$scenario", $ENV{TEST_NGINX_SERVER_PORT})
        }
    };
}
our $Config = q{
    location /expire {
        content_by_lua_block { require('resty.peter_sslers').expire_ssl_certs() }
    }
    location /t {
        content_by_lua_block {
            local control = ngx.shared.cache_control
            local deadline = ngx.now() + 7
            while not control:get('reader_done') do
                assert(not control:get('error'), control:get('error'))
                assert(ngx.now() < deadline, 'cache worker test timed out')
                ngx.sleep(0.01)
            end
            ngx.say('ok')
        }
    }
};
master_on();
workers(2);
no_long_string();
run_tests();

__DATA__

=== TEST: storage
--- http_config eval: main::cache_config("storage")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: set
--- http_config eval: main::cache_config("set")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: negative
--- http_config eval: main::cache_config("negative")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: delete
--- http_config eval: main::cache_config("delete")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: purge
--- http_config eval: main::cache_config("purge")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: ttl
--- http_config eval: main::cache_config("ttl")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: singleflight
--- http_config eval: main::cache_config("singleflight")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted
