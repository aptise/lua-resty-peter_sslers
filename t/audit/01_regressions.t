use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

our $pwd = cwd();
no_long_string();
run_tests();

__DATA__

=== TEST: domain expiration removes both parts
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("expire")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: Redis connect errors are preserved
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("connect")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: Redis SELECT failure rejects connection
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("select")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: corrupt Redis PEM falls through to API
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("corrupt")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: API transport failure permits recovery
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("outage")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: scalar JSON does not throw
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("scalar")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: incomplete certificate JSON does not throw
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("nested")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: malformed autocert response cleans marker
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("autocert")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: successful API lookup is reused
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("happy")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: failed cache write never exposes mixed pair
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("write_failure")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: invalid_sni
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("invalid_sni")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: canonical_sni
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("canonical_sni")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: lock_busy
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("lock_busy")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: api_exception
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("api_exception")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: malformed_retry
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("malformed_retry")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: malformed_retry_autocert
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("malformed_retry_autocert")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: absence_cached
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("absence_cached")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: lease_replaced
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("lease_replaced")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: lease_exception
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("lease_exception")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: lease_expired
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("lease_expired")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: lease_new_certificate
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("lease_new_certificate")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST: lease_tokens
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/regressions.lua"))()
            run("lease_tokens")
            ngx.say("ok")
        }
    }
}
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
