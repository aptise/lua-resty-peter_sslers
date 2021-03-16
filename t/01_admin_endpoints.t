use Test::Nginx::Socket 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();

$ENV{TEST_NGINX_RESOLVER} = '8.8.8.8';
$ENV{TEST_NGINX_PWD} ||= $pwd;
$ENV{TEST_COVERAGE} ||= 0;

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

run_tests();

__DATA__
=== TEST 1: admin endpoint- expire
--- http_config eval: $::HttpConfig
--- config
    ## enable a cache expiry route
	location  /.peter_sslers/nginx/shared_cache/expire  {
		content_by_lua_block  {
			-- requirements
			local ssl_certhandler = require "peter_sslers.ssl_certhandler"

			-- alias functions
			local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs
			ssl_certhandler_expire()
		}
	}
--- request
GET /a
--- response_body
OK
--- no_error_log
[error]
[warn]


=== TEST 2: admin endpoint- status
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
}
--- request
GET /a
--- response_body
OK
--- no_error_log
[error]
[warn]
