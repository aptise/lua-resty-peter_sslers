use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

our $pwd = cwd();
no_long_string();
run_tests();

__DATA__

=== TEST: redis_hmget_false_1
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_hmget_false_1")
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

=== TEST: redis_hmget_false_2
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_hmget_false_2")
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

=== TEST: redis_shape_1
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_shape_1")
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

=== TEST: redis_shape_2
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_shape_2")
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

=== TEST: redis_partial_1
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_partial_1")
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

=== TEST: redis_partial_2
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_partial_2")
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

=== TEST: redis_get_false_p
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_get_false_p")
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

=== TEST: redis_get_false_c
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_get_false_c")
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

=== TEST: redis_get_false_i
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_get_false_i")
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

=== TEST: redis_get_absent
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_get_absent")
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

=== TEST: redis_retry_1
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_retry_1")
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

=== TEST: redis_retry_2
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_retry_2")
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

=== TEST: redis_missing_1
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_missing_1")
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

=== TEST: redis_missing_2
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_missing_2")
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

=== TEST: redis_reuse_error
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_reuse_error")
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

=== TEST: redis_pipeline_timeout
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_pipeline_timeout")
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

=== TEST: redis_pipeline_shape
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_pipeline_shape")
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

=== TEST: redis_pipeline_partial
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_pipeline_partial")
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

=== TEST: redis_pipeline_retry
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/redis_errors.lua"))()
            run("redis_pipeline_retry")
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
