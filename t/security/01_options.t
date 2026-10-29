use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
our $pwd = cwd();
our $HttpConfig = qq{lua_package_path "$pwd/lib/?.lua;;"; lua_shared_dict cert_cache 100k;
    lua_shared_dict cert_cache_ipc 100k;};
no_long_string();
run_tests();

__DATA__

=== TEST: unknown
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("unknown")
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

=== TEST: username_only
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("username_only")
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

=== TEST: cert_only
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("cert_only")
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

=== TEST: cert_plaintext
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("cert_plaintext")
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

=== TEST: invalid_cert
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("invalid_cert")
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

=== TEST: invalid_key
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("invalid_key")
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

=== TEST: invalid_timeout
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("invalid_timeout")
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

=== TEST: invalid_verify
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("invalid_verify")
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

=== TEST: false_cert
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("false_cert")
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

=== TEST: header_injection
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("header_injection")
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

=== TEST: conflicting_auth
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("conflicting_auth")
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

=== TEST: unsupported_mtls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("unsupported_mtls")
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

=== TEST: auth_failure
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("auth_failure")
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

=== TEST: unsupported_tls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("unsupported_tls")
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

=== TEST: unsupported_http_mtls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/options.lua"))()
            run("unsupported_http_mtls")
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

=== TEST: negative_backoff
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/security/options.lua"))()("negative_backoff")
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

=== TEST: excessive_backoff
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/security/options.lua"))()("excessive_backoff")
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

=== TEST: infinite_backoff
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/security/options.lua"))()("infinite_backoff")
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
