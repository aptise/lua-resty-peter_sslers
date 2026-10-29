use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
our $pwd = cwd();
sub retry_config {
    my ($case) = @_;
    return qq{
        lua_package_path "$pwd/lib/?.lua;;";
        lua_shared_dict cert_cache 1m;
        lua_shared_dict cert_cache_ipc 100k;
        lua_shared_dict retry_control 100k;
        init_worker_by_lua_block {
            assert(loadfile("$pwd/t/cache/retry_workers.lua"))()("$case")
        }
    };
}
our $Config = q{
    location /t {
        content_by_lua_block {
            local control = ngx.shared.retry_control
            local deadline = ngx.now() + 5
            while not control:get('writer_done') do
                assert(not control:get('error'), control:get('error'))
                assert(ngx.now() < deadline, 'retry test timed out')
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

=== TEST: api
--- http_config eval: main::retry_config("api")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: redis
--- http_config eval: main::retry_config("redis")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: fallback
--- http_config eval: main::retry_config("fallback")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: cached
--- http_config eval: main::retry_config("cached")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: absence
--- http_config eval: main::retry_config("absence")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: autocert
--- http_config eval: main::retry_config("autocert")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: exception
--- http_config eval: main::retry_config("exception")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: disabled
--- http_config eval: main::retry_config("disabled")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: identity
--- http_config eval: main::retry_config("identity")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: domain_failure
--- http_config eval: main::retry_config("domain_failure")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: success_reset
--- http_config eval: main::retry_config("success_reset")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted
