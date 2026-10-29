use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
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

=== TEST: mismatch
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("mismatch")
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

=== TEST: shared_mismatch
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("shared_mismatch")
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

=== TEST: bad_cert
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("bad_cert")
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

=== TEST: bad_key
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("bad_key")
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

=== TEST: clear_failure
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("clear_failure")
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

=== TEST: cert_failure
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("cert_failure")
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

=== TEST: key_failure
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("key_failure")
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

=== TEST: redis_fallback
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("redis_fallback")
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

=== TEST: success
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("success")
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

=== TEST: chain_mismatch
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/audit/installation.lua"))()("chain_mismatch")
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
