use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
BEGIN {
    unless ($ENV{TEST_SECURITY_DIR}) {
        require Test::More;
        Test::More::plan(skip_all => 'Run t/security/run.py --full-suite for isolated DNS fixtures');
    }
}
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
use JSON::PP qw(decode_json);
our $pwd = cwd();
open my $ports_file, '<', "$ENV{TEST_SECURITY_DIR}/ports.json" or die $!;
our $ports = decode_json(do { local $/; <$ports_file> });
close $ports_file;
sub dns_config {
    my ($case) = @_;
    my $resolver = $case eq 'no_resolver' ? '' : "resolver 127.0.0.1:$ports->{dns} valid=1s ipv6=off;";
    return qq{
        lua_package_path "$pwd/lib/?.lua;;";
        lua_shared_dict cert_cache 1m;
        lua_shared_dict cert_cache_ipc 100k;
        $resolver
        resolver_timeout 100ms;
    };
}
no_long_string();
run_tests();

__DATA__

=== TEST: nx
--- http_config eval: main::dns_config("nx")
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/resolvers.lua"))()("nx", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: fail
--- http_config eval: main::dns_config("fail")
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/resolvers.lua"))()("fail", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: drop
--- http_config eval: main::dns_config("drop")
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/resolvers.lua"))()("drop", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: malformed
--- http_config eval: main::dns_config("malformed")
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/resolvers.lua"))()("malformed", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: no_resolver
--- http_config eval: main::dns_config("no_resolver")
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/resolvers.lua"))()("no_resolver", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: recover
--- http_config eval: main::dns_config("recover")
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/resolvers.lua"))()("recover", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: redis_failover
--- http_config eval: main::dns_config("redis_failover")
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/network/resolvers.lua"))()("redis_failover", "$ENV{TEST_SECURITY_DIR}")
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
