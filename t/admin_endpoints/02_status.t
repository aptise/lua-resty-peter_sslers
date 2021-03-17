use Test::Nginx::Socket 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
$ENV{TEST_NGINX_RESOLVER} = '8.8.8.8';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;/usr/local/share/lua/5.1/?.lua;;";
    error_log logs/error.log debug;

    lua_shared_dict  cert_cache 100k;
    lua_code_cache  on;

    init_by_lua_block {
        require "resty.core"

        if $ENV{TEST_COVERAGE} == 1 then
            jit.off()
            require("luacov.runner").init()
        end

        local ssl_certhandler = require "peter_sslers.ssl_certhandler"
        ssl_certhandler.initialize()
    }

    init_worker_by_lua_block {
        require "resty.core"
        local ssl_certhandler = require "peter_sslers.ssl_certhandler"
        -- cert_cache_duration, lru_cache_duration, lru_maxitems
        ssl_certhandler.initialize_worker(600, 60, 200)
    }

};

no_long_string();
#no_diff();

log_level("debug");
run_tests();

__DATA__
=== TEST 1: admin endpoint- status
--- http_config eval: $::HttpConfig
--- config
	## enable a status route
	location  /.peter_sslers/nginx/shared_cache/status  {
		content_by_lua_block  {
			-- requirements
			local ssl_certhandler = require "peter_sslers.ssl_certhandler"

			-- alias functions
			local ssl_certhandler_status = ssl_certhandler.status_ssl_certs
			ssl_certhandler_status()
		}
	}
--- request
GET /.peter_sslers/nginx/shared_cache/status
--- response_body_like
\{"result": "success", "note": "This is a max\(1024\) listening of keys in the ngx\.shared\.DICT `cert_cache`\. This does not show the worker's own LRU cache, or Redis\.", "keys": \{"valid": \[\], "invalid": \[\], "autocert": \[\]\}, "config": \{"expiries": \{"ngx\.shared\.cert_cache": 600, "resty\.lrucache": 60\}, "maxitems": \{"resty\.lrucache": 200\}\}, "server": "peter_sslers:openresty", "server_version": "\d+\.\d+\.\d+"\}
--- response_headers_like
x-peter-sslers: \d+\.\d+\.\d+
--- error_log
[notice]
ssl_certhandler.initialize
ssl_certhandler.initialize_worker
status_ssl_certs
--- no_error_log
[error]
[warn]
