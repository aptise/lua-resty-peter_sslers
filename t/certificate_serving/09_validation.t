use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
our $pwd = cwd();
our $html = html_dir();
sub validation_http {
    my ($case) = @_;
    return qq{
        lua_package_path "$pwd/lib/?.lua;;";
        lua_shared_dict cert_cache 1m;
        lua_shared_dict cert_cache_ipc 100k;
        lua_shared_dict installation_control 100k;
        lua_ssl_trusted_certificate "$pwd/t/cert/_all.crt";
        init_worker_by_lua_block {
            local ssl = require 'ngx.ssl'
            local wrapped = {}
            for k, v in pairs(ssl) do wrapped[k] = v end
            for _, entry in ipairs({{'clear', 'clear_certs'}, {'cert', 'set_cert'}, {'key', 'set_priv_key'}}) do
                local name, fn = entry[1], ssl[entry[2]]
                wrapped[entry[2]] = function(...)
                    ngx.shared.installation_control:incr('steps', 1, 0)
                    if "$case" == name .. '_failure' then return nil, 'injected installation failure' end
                    return fn(...)
                end
            end
            package.loaded['ngx.ssl'] = wrapped
            local handler = require 'resty.peter_sslers'
            package.loaded['ngx.ssl'] = ssl
            handler.initialize_worker(600, 60, 200)
        }
        server {
            listen unix:$html/validation.sock ssl;
            ssl_certificate "$pwd/t/cert/example.com.crt";
            ssl_certificate_key "$pwd/t/cert/example.com.key";
            ssl_certificate_by_lua_block {
                require('resty.peter_sslers').set_ssl_certificate(nil,
                    "$case" ~= 'shared_mismatch' and 'http://127.0.0.1:$ENV{TEST_NGINX_SERVER_PORT}/backend' or nil, nil)
            }
        }
    };
}
sub validation_config {
    my ($case) = @_;
    return qq{
        location /backend {
            content_by_lua_block {
                local function read(path)
                    local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
                end
                local key = "$case" == 'mismatch' and 'example.com' or 'test.example.com'
                ngx.say(assert(require('cjson.safe').encode({certificate_signed__latest_multi = {
                    fullchain = {pem = read('t/cert/test.example.com.crt')},
                    private_key = {pem = read('t/cert/' .. key .. '.key')}}})))
            }
        }
        location /t {
            content_by_lua_block {
                assert(loadfile("$pwd/t/certificate_serving/validation.lua"))()("$case", "$html/validation.sock")
                ngx.say('ok')
            }
        }
    };
}
no_long_string();
run_tests();

__DATA__

=== TEST: mismatch
--- http_config eval: main::validation_http("mismatch")
--- config eval: main::validation_config("mismatch")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: shared_mismatch
--- http_config eval: main::validation_http("shared_mismatch")
--- config eval: main::validation_config("shared_mismatch")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: success
--- http_config eval: main::validation_http("success")
--- config eval: main::validation_config("success")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: clear_failure
--- http_config eval: main::validation_http("clear_failure")
--- config eval: main::validation_config("clear_failure")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: cert_failure
--- http_config eval: main::validation_http("cert_failure")
--- config eval: main::validation_config("cert_failure")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: key_failure
--- http_config eval: main::validation_http("key_failure")
--- config eval: main::validation_config("key_failure")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted
