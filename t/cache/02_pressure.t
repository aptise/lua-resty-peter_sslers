use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
our $pwd = cwd();
our $html = html_dir();
sub pressure_http {
    my ($case) = @_;
    my $size = $case eq 'oversized' ? '16k' : '32k';
    return qq{
        lua_package_path "$pwd/lib/?.lua;;";
        lua_shared_dict cert_cache $size;
        lua_shared_dict cert_cache_ipc 100k;
        lua_shared_dict pressure_control 100k;
        lua_ssl_trusted_certificate "$pwd/t/cert/_all.crt";
        init_worker_by_lua_block { require('resty.peter_sslers').initialize_worker(600, 60, 200) }
        server {
            listen unix:$html/pressure.sock ssl;
            ssl_certificate "$pwd/t/cert/example.com.crt";
            ssl_certificate_key "$pwd/t/cert/example.com.key";
            ssl_certificate_by_lua_block {
                require('resty.peter_sslers').set_ssl_certificate(nil,
                    'http://127.0.0.1:$ENV{TEST_NGINX_SERVER_PORT}/backend', nil)
            }
        }
    };
}
our $Config = qq{
    location /backend {
        content_by_lua_block {
            ngx.shared.pressure_control:incr('api_calls', 1, 0)
            local function read(path)
                local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
            end
            ngx.say(assert(require('cjson.safe').encode({certificate_signed__latest_multi = {
                fullchain = {pem = string.rep(read('t/cert/test.example.com.crt'), 16)},
                private_key = {pem = read('t/cert/test.example.com.key')},
            }})))
        }
    }
};
no_long_string();
run_tests();

__DATA__

=== TEST: churn
--- http_config eval: main::pressure_http("churn")
--- config eval
$::Config . qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/cache/pressure.lua"))()("churn", "$::html/pressure.sock")
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

=== TEST: oversized
--- http_config eval: main::pressure_http("oversized")
--- config eval
$::Config . qq{
    location /t {
        content_by_lua_block {
            assert(loadfile("$::pwd/t/cache/pressure.lua"))()("oversized", "$::html/pressure.sock")
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
