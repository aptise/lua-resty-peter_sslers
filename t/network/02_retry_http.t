use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
BEGIN {
    unless ($ENV{TEST_SECURITY_DIR}) {
        require Test::More;
        Test::More::plan(skip_all => 'Run t/security/run.py --full-suite for retry HTTP fixtures');
    }
}
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
our $pwd = cwd();
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    lua_shared_dict cert_cache 1m;
    lua_shared_dict cert_cache_ipc 100k;
};
no_long_string();
run_tests();

__DATA__

=== TEST: real HTTP 503 cooldown and recovery
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/retry_http.lua"))()("$ENV{TEST_SECURITY_DIR}")
            ngx.say('ok')
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted
