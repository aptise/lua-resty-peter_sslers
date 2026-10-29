use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
BEGIN {
    unless ($ENV{TEST_SECURITY_DIR}) {
        require Test::More;
        Test::More::plan(skip_all => 'Run t/security/run.py to start isolated secure fixtures');
    }
}
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
our $pwd = cwd();
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    lua_shared_dict cert_cache 1m;
    lua_ssl_trusted_certificate "$ENV{TEST_SECURITY_DIR}/ca.crt";
    lua_ssl_verify_depth 2;
};
no_long_string();
run_tests();

__DATA__

=== TEST: prime_formats
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("prime_formats", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_password
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_password", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_acl
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_acl", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_missing_password
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_missing_password", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_wrong_password
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_wrong_password", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_tls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_tls", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_bad_hostname_tls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_bad_hostname_tls", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_mtls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_mtls", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_missing_cert_mtls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_missing_cert_mtls", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_pool_credentials
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_pool_credentials", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_http
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_http", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_https
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_https", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_autocert
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_autocert", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_bearer
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_bearer", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_wrong_password
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_wrong_password", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_wrong_hostname
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_wrong_hostname", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_untrusted
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_untrusted", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_mtls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_mtls", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_missing_cert_mtls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_missing_cert_mtls", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: api_pool_identity_mtls
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("api_pool_identity_mtls", "$ENV{TEST_SECURITY_DIR}")
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

=== TEST: store_pool_db
--- http_config eval: $::HttpConfig
--- config eval
qq{
    location /t {
        content_by_lua_block {
            local run = assert(loadfile("$::pwd/t/security/integration.lua"))()
            run("store_pool_db", "$ENV{TEST_SECURITY_DIR}")
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
