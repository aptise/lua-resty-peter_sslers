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
