# lua-resty-peter_sslers

Lua support for https://github.com/aptise/peter_sslers Certificate Manager in OpenResty

# Status

Beta but Production ready.

# API

* [new](#name)
* [connect](#connect)
* [set_timeout](#set_timeout)
* [ssl_handshake](#ssl_handshake)
* [set_keepalive](#set_keepalive)
* [get_reused_times](#get_reused_times)
* [close](#close)
* [request](#request)
* [request_uri](#request_uri)
* [request_pipeline](#request_pipeline)
* [Response](#response)
    * [body_reader](#resbody_reader)
    * [read_body](#resread_body)
    * [read_trailes](#resread_trailers)
* [Proxy](#proxy)
    * [proxy_request](#proxy_request)
    * [proxy_response](#proxy_response)
* [Utility](#utility)
    * [parse_uri](#parse_uri)
    * [get_client_body_reader](#get_client_body_reader)


## Synopsis

`lua-resty-peter_sslers` is a library that can be used in an openresty/nginx environment to dynamically serve the correct SSL certificate for a given domain.

It supports both the prime cache types 1 & 2 of `peter_sslers`

It is implemented as a library with 2 example scripts to invoke it.

* `ssl_certhandler.lua`
* `ssl_certhandler-lookup.lua`
* `ssl_certhandler-expire.lua`

The `-lookup.lua` and `-expire.lua` scripts can set via `_by_lua_file` or copied into a block.  

The library is hardcoded to use db9 in redis.  if you want another option, edit or PR a fix on the line that looks like:

	ngx.log(ngx.ERR, "changing to db 9: ", times)
	redcon:select(9)
	
Redis is NOT required, but recommended.  Instead you can failover to directly query a peter_sslers pyramid instance.

To use the Peter SSlers Pyramid fallback, the following library is used:

* lua-resty-http https://github.com/pintsized/lua-resty-http


Hits and misses from the fallback API will be cached in the shared cache dict.  If you need to remove values, you will need to restart the server OR use one of the nginx/lua examples for cache clearing.  Fallback API requests will notify the Pyramid app that the request should have write-through cache behavior.


### ssl_certhandler.lua

Core library.  Exposes several functions.

Make sure your nginx contains:

````
    server {
		init_by_lua 'require "resty.core"';
	    lua_shared_dict cert_cache 1m;
	}
````


### ssl_certhandler-lookup.lua

This is very simple, it merely specfies a cache, duration, and prime_version

````
	local ssl_certhandler = require "ssl_certhandler"

	-- Local cache related
	local cert_cache = ngx.shared.cert_cache
	local cert_cache_duration = 7200 -- 2 hours

	local prime_version = 1
    local fallback_server = 'http://0.0.0.0:6543'
	ssl_certhandler.set_ssl_certificate(cert_cache, cert_cache_duration, prime_version, fallback_server)

	return
````

invoked within nginx...

````
    server {
        listen 443 default_server;
        ...
		ssl_certificate_by_lua_file /path/to/ssl_certhandler-lookup.lua;
	}
````


### ssl_certhandler-expire.lua

The nginx shared memory cache persists across configuration reloads.  Servers must be fully restarted to clear memory.

The workaround?  API endpoints to "flush" the cache or expire certain keys(domains):

````
	local ssl_certhandler = require "ssl_certhandler"

	-- Local cache related
	local cert_cache = ngx.shared.cert_cache

	ssl_certhandler.expire_ssl_certs(cert_cache)
````

invoked within nginx

````
    server {
        listen 443 default_server;
        ...
	    location /ngxadmin/shared_cache/expire {
			content_by_lua_file /path/to/ssl_certhandler-expire.lua;
	    }
	}
````
	
This creates the following routes:

* `/ngxadmin/shared_cache/expire/all`
** Flushes the entire nginx certificate cache
* `/ngxadmin/shared_cache/expire/domain/{DOMAIN}`
** Flushes the domain's pkey & chain entires in the certificate cache

On success, these routes return JSON in a HTTP-200-OK document.

* {"result": "success", "expired": "all"}
* {"result": "success", "expired": "domain", "domain": "{DOMAIN}"}
* {"result": "error", "expired": "None", "reason": "Unknown URI"}

On error, these routes should generate a bad status code.

The Pyramid component can query these endpoints automatically for you.

### Details

This approach makes aggressive use of caching in the nginx workers (via a shared dict) and redis; and caches both hits and misses.

The nginx worker dicts are shared across reloads (`kill -HUP {PID}`); so if a bad value gets in there you must restart or wait for the timeout.

The logic in pseudocode:

````
	# grab certs
	(key, fullchain) = cert_cache.get(domain)
	if all((key, fullchain)):
		if (key == 'x') or (fullchain == 'x'):
			# default cert is still active
			return
	else:
		(key, fullchain) = redis.get(domain)
		# redis is a write-through cache
		if all((key, fullchain)):
			cert_cache.set(domain, key, fullchain)
		else:
			# mark domain invalid		
			cert_cache.set(domain, 'x', 'x')
			# default cert is still active
			return
	ssl.clear_certs()
	ssl.set_der_cert(cert)
	ssl.set_der_priv_key(key)
````


# Author

Jonathan Vanasco <jonathan@findmeon.com>

Originally started in https://github.com/aptise/peter_sslers


# Licence

This module is licensed under the MIT License.  See `LICENSE.txt`
