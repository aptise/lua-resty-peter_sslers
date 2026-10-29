use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

our $pwd = cwd();
sub worker_config {
    my ($scenario) = @_;
    return qq{
        lua_package_path "$pwd/lib/?.lua;;";
        lua_shared_dict cert_cache 1m;
    lua_shared_dict cert_cache_ipc 100k;
        lua_shared_dict audit_control 100k;
        init_worker_by_lua_block {
            local start = assert(loadfile("$pwd/t/audit/autocert_workers.lua"))()
            start("$scenario")
        }
    };
}
our $Config = q{
    location /t {
        content_by_lua_block {
            local control = ngx.shared.audit_control
            local deadline = ngx.now() + 7
            while not control:get('contender_done') do
                assert(not control:get('error'), control:get('error'))
                assert(ngx.now() < deadline, 'timed out waiting for worker results')
                ngx.sleep(0.01)
            end
            assert(control:get('owner_done'), 'owner did not finish')
            assert(control:get('owner_pid') ~= control:get('contender_pid'), 'workers were not distinct')
            ngx.say('ok')
        }
    }
};
master_on();
workers(2);
no_long_string();
run_tests();

__DATA__

=== TEST: pending with two real workers
--- http_config eval: main::worker_config("pending")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: replaced with two real workers
--- http_config eval: main::worker_config("replaced")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: exception with two real workers
--- http_config eval: main::worker_config("exception")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: expired with two real workers
--- http_config eval: main::worker_config("expired")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: new_certificate with two real workers
--- http_config eval: main::worker_config("new_certificate")
--- config eval: $::Config
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
