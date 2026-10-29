use FindBin qw($Bin);
use lib "$Bin/../lib";
use PeterSSLers::TestConfig;
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

our $pwd = cwd();
$ENV{REDIS_HOST} ||= '127.0.0.1';
$ENV{REDIS_PORT} ||= '6379';
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    lua_shared_dict cert_cache 100k;
    init_worker_by_lua_block {
        local handler = require 'resty.peter_sslers'
        handler.redis_update_defaults("$ENV{REDIS_HOST}", "$ENV{REDIS_PORT}", 9)
    }
};
sub error_config {
    my ($scenario) = @_;
    return qq{
        location /t {
            content_by_lua_block {
                local handler = require 'resty.peter_sslers'
                local redcon = assert(handler.get_redcon())
                local domain = 'redis-audit-' .. ngx.worker.pid() .. '.example.com'
                local keys = {'d1:' .. domain, 'd2:' .. domain,
                    'p:' .. domain, 'c:' .. domain, 'i:' .. domain}
                local strategy = "$scenario" == 'hmget2' and 2 or 1
                assert(redcon:del(unpack(keys)))
                local prepared, preparation_err = pcall(function()
                    if "$scenario" == 'hmget1' or "$scenario" == 'hmget2' then
                        assert(redcon:set('d' .. strategy .. ':' .. domain, 'not a hash'))
                    else
                        assert(redcon:hmset('d1:' .. domain, 'c', domain, 'p', domain, 'i', domain))
                        for _, prefix in ipairs({'p:', 'c:', 'i:'}) do
                            assert(redcon:set(prefix .. domain, 'pem placeholder'))
                        end
                        local key = "$scenario" .. ':' .. domain
                        assert(redcon:del(key))
                        assert(redcon:hset(key, 'field', 'not a string'))
                    end
                end)
                local query = strategy == 1 and handler.prime_1__query_redis or handler.prime_2__query_redis
                local ok, pair, err
                if prepared then ok, pair, err = pcall(query, redcon, domain) end
                -- Always remove this worker's fixture keys, including on failure.
                assert(redcon:del(unpack(keys)))
                handler.redis_keepalive(redcon)
                assert(prepared, preparation_err)
                assert(ok, pair)
                assert(pair == nil and type(err) == 'string' and err:find('WRONGTYPE', 1, true),
                    'Redis WRONGTYPE must be returned as a recoverable query error')
                ngx.say('ok')
            }
        }
    };
}
no_long_string();
run_tests();

__DATA__

=== TEST: real Redis wrong-type hmget1
--- http_config eval: $::HttpConfig
--- config eval: main::error_config("hmget1")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: real Redis wrong-type hmget2
--- http_config eval: $::HttpConfig
--- config eval: main::error_config("hmget2")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: real Redis wrong-type p
--- http_config eval: $::HttpConfig
--- config eval: main::error_config("p")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: real Redis wrong-type c
--- http_config eval: $::HttpConfig
--- config eval: main::error_config("c")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted

=== TEST: real Redis wrong-type i
--- http_config eval: $::HttpConfig
--- config eval: main::error_config("i")
--- request
GET /t
--- response_body
ok
--- no_error_log
lua entry thread aborted
