use Test::Nginx::Socket 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
$ENV{TEST_NGINX_RESOLVER} = '1.1.1.1';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    error_log logs/error.log debug;

    lua_shared_dict  cert_cache 100k;
    lua_code_cache  on;
    init_by_lua_block {
        require "resty.core"
        local ssl_certhandler = require "resty.peter_sslers"
        ssl_certhandler.initialize()
    }
    init_worker_by_lua_block {
        require "resty.core"
        local ssl_certhandler = require "resty.peter_sslers"
        -- cert_cache_duration, lru_cache_duration, lru_maxitems
        ssl_certhandler.initialize_worker(600, 60, 200)
    }
};
no_long_string();
#no_diff();
log_level("debug");
run_tests();

__DATA__
=== TEST 1: admin endpoint- expire - no domain
--- http_config eval: $::HttpConfig
--- config
    ## enable a cache expiry route
	location  /.peter_sslers/nginx/shared_cache/expire  {
		content_by_lua_block  {
			-- requirements
			local ssl_certhandler = require "resty.peter_sslers"

			-- alias functions
			local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs
			ssl_certhandler_expire()
		}
	}
--- request
GET /.peter_sslers/nginx/shared_cache/expire
--- response_body_like
{"result": "error", "expired": "None", "reason": "Unknown URI", "server": "peter_sslers:openresty", "server_version": "\d+\.\d+\.\d+"}
--- response_headers_like
x-peter-sslers: \d+\.\d+\.\d+
--- error_code: 404
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
[error]
expire_ssl_certs - malformed request
--- no_error_log
[warn]


=== TEST 2: admin endpoint- expire - all
--- http_config eval: $::HttpConfig
--- config
    ## enable a cache expiry route
	location  /.peter_sslers/nginx/shared_cache/expire  {
		content_by_lua_block  {
			-- requirements
			local ssl_certhandler = require "resty.peter_sslers"

			-- alias functions
			local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs
			ssl_certhandler_expire()
		}
	}
--- request
GET /.peter_sslers/nginx/shared_cache/expire/all
--- response_body_like
{"result": "success", "expired": "all", "server": "peter_sslers:openresty", "server_version": "\d+\.\d+\.\d+"}
--- response_headers_like
x-peter-sslers: \d+\.\d+\.\d+
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
--- no_error_log
[error]
[warn]


=== TEST 3: admin endpoint- expire - domain - example.com
--- http_config eval: $::HttpConfig
--- config
    ## enable a cache expiry route
	location  /.peter_sslers/nginx/shared_cache/expire  {
		content_by_lua_block  {
			-- requirements
			local ssl_certhandler = require "resty.peter_sslers"

			-- alias functions
			local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs
			ssl_certhandler_expire()
		}
	}
--- request
GET /.peter_sslers/nginx/shared_cache/expire/domain/example.com
--- response_body_like
{"result": "success", "expired": "domain", "domain": "example.com", "server": "peter_sslers:openresty", "server_version": "\d+\.\d+\.\d+"}
--- response_headers_like
x-peter-sslers: \d+\.\d+\.\d+
--- error_log
[notice]
peter_sslers.initialize
peter_sslers.initialize_worker
expire_ssl_certs
--- no_error_log
[error]
[warn]