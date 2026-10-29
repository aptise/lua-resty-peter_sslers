use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

our $pwd = cwd();
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    lua_shared_dict cert_cache 100k;
};
no_long_string();
log_level("debug");
run_tests();

__DATA__

=== TEST: invalid_json
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("invalid_json")
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

=== TEST: scalar
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
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

=== TEST: json_null
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("json_null")
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

=== TEST: array
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("array")
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

=== TEST: empty_object
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("empty_object")
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

=== TEST: incomplete
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("incomplete")
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

=== TEST: missing_preference
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("missing_preference")
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

=== TEST: wrong_type
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("wrong_type")
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

=== TEST: error_response
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("error_response")
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

=== TEST: explicit_absence
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("explicit_absence")
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

=== TEST: not_found_metadata
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("not_found_metadata")
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

=== TEST: success_metadata
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("success_metadata")
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

=== TEST: fallback_preference
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/audit/api_responses.lua"))()
            run("fallback_preference")
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
