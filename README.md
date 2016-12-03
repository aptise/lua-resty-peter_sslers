# lua-resty-peter_sslers

Lua support for https://github.com/aptise/peter_sslers Certificate Manager in OpenResty

# Status

This package is almost production-ready.

# Installation

one line...

    sudo opm install aptise/peter_sslers-lua-resty

## Synopsis

`lua-resty-peter_sslers` is a library that can be used in an openresty/nginx environment to dynamically serve the correct SSL certificate for a given domain.

It supports both the prime cache types 1 & 2 of `peter_sslers`

It is implemented as a library with some example scripts to invoke it.

* core library
  * `ssl_certhandler.lua`
* examples
  * `ssl_certhandler-lookup.lua`
  * `ssl_certhandler-expire.lua`
  * `ssl_certhandler-status.lua`

The `-lookup.lua`, `-expire.lua`,  `-status.lua` scripts can be copied into a block.  

The library is hardcoded to use db9 in redis.  if you want another option, edit or PR a fix on the line that looks like:

	ngx.log(ngx.ERR, "changing to db 9: ", times)
	redcon:select(9)
	
Redis is NOT required, but recommended.  Instead you can failover to directly query a peter_sslers pyramid instance.

To use the Peter SSlers Pyramid fallback, the following library is used:

* lua-resty-http https://github.com/pintsized/lua-resty-http

Hits and misses from the fallback API will be cached in the shared cache dict.  If you need to remove values, you will need to restart the server OR use one of the nginx/lua examples for cache clearing.  Fallback API requests will notify the Pyramid app that the request should have write-through cache behavior.

### Caching Note

In order to maximize performance there are 2 layers of caching WITHIN nginx/openresty:

* certificates are cached in a LRU cache within a given worker in the native cdata format for `ssl_certhandler.lru_cache_duration` seconds (default 60)
* certificates are cached across all workers in PEM format for `ssl_certhandler.cert_cache_duration` seconds (default 600)

These values can be adjusted.

Why?

The nginx shared dict can easily have values queried flushed/expired/overwritten, however it can only store PEM certificates (not the cdata pointers), so the certificates need to be repeatedly parsed.

The LRU cache can hold the cdata pointers, but implementation details of nginx/openresty do not allow easy query & manipulation of the cache. Messaging between all the workers for overwriting/expiry would be a large task too.

An easy way to handle deployment concerns is to use a timeout on the LRU cache that is long-enough to perform well under load, but short-enough to allow for changes in the shared-dict to propagate.


## Usage

Make sure your nginx contains:

````
    server {
		init_by_lua_block {
			require "resty.core"
			local ssl_certhandler = require "peter_sslers.ssl_certhandler"
			ssl_certhandler.initialize()
		}
		init_worker_by_lua_block {
			require "resty.core"
			local ssl_certhandler = require "peter_sslers.ssl_certhandler"
			-- cert_cache_duration, lru_cache_duration, lru_maxitems
			ssl_certhandler.initialize_worker(9, 3, 200)
		}
	}
````

* `initialize` currently does nothing.
* `initialize_worker` accepts three arguments:
  * `cert_cache_duration` seconds for PEM cache in ngx.shared.DICT
  * `lru_cache_duration` seconds for LRU cache of cdata pointer in worker
  * `lru_maxitems` max number of items for LRU cache of cdata pointer in worker

Then implement the examples routes

Due to an implementation detail of lua/luajit, the examples below must be implemented in a block/file and can not be "require(/path/to/example)".  This is because of how the redis connection is instantiated.  (see https://github.com/openresty/lua-resty-redis/issues/33 https://github.com/openresty/lua-nginx-module/issues/376 )

### ssl_certhandler.lua

Core library.  Exposes several functions.


### examples/ssl_certhandler-lookup.lua

This is very simple, it merely specfies a cache, duration, and prime_version

invoked within nginx...

````
    server {
        listen 443 default_server;
        ...
        // nginx must have a default configured
        ssl_certificate /path/to/default/fullchain.pem;
        ssl_certificate_key /path/to/default/privkey.pem;
		ssl_certificate_by_lua_block  {
		}
````

### examples/ssl_certhandler-expire.lua

The nginx shared memory cache persists across configuration reloads.  Servers must be fully restarted to clear memory.

The workaround?  API endpoints to "flush" the cache or expire certain keys(domains).

A simple example is provided with `peter_sslers.ssl_certhandler-expire`,  which can be invoked within nginx as-is rather easily:

````
    server {
        listen 443 default_server;
        ...
        location  /.peter_sslers  {
            auth_basic  "peter_sslers-nginx";
            auth_basic_user_file  /path/to/peter_sslers-nginx.htpasswd;
			location  /.peter_sslers/nginx/shared_cache/expire  {
				content_by_lua_block  {
					-- requirements
					local ssl_certhandler = require "peter_sslers.ssl_certhandler"

					-- alias functions
					local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs
					ssl_certhandler_expire()
				}
			}
		}
	}
````

This expire tool creates the following routes:

* `/peter_sslers/nginx/shared_cache/expire/all`
** Flushes the entire nginx certificate cache
* `/peter_sslers/nginx/shared_cache/expire/domain/{DOMAIN}`
** Flushes the domain's pkey & chain entires in the certificate cache

On success, these routes return JSON in a HTTP-200-OK document.

* {"result": "success", "expired": "all"}
* {"result": "success", "expired": "domain", "domain": "{DOMAIN}"}
* {"result": "error", "expired": "None", "reason": "Unknown URI"}

On error, these routes should generate a bad status code.

The Pyramid component can query these endpoints automatically for you.


### examples/ssl_certhandler-status.lua

The status route shows some info about the system

````
    server {
        listen 443 default_server;
        ...
        location  /.peter_sslers/nginx  {
            auth_basic  "peter_sslers-nginx";
            auth_basic_user_file  /path/to/peter_sslers-nginx.htpasswd;
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
	}
````
	
### examples/ssl_certhandler-lookup.lua

This the core work:

````
        ssl_certificate_by_lua_block  {
            -- requirements
            local ssl_certhandler = require "peter_sslers.ssl_certhandler"

            -- alias functions
            local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate

            local prime_version = 1
            local fallback_server = 'http://0.0.0.0:6543'
            ssl_certhandler_set(prime_version, fallback_server)
        }
````


### fully configured example

a fully configured example is available in the main peter_sslers repo: https://github.com/aptise/peter_sslers/blob/master/tools/nginx_conf/enabled.conf

### Details

This approach makes aggressive use of caching in the nginx workers (via worker lru and a shared dict) and Redis; caching both hits and misses.

The nginx worker dicts are shared across reloads (`kill -HUP {PID}`); so if a bad value gets in there you must restart or wait for the timeout.

The logic in pseudocode:

````
	cert_cdata = lru_cache.get(domain)  # check worker cache
	if hit(cert_cdata):
		if invalid(cert_cdata):
			return
	else:
		cert_pem =	cert_cache.get(domain)  # check shared cache
		if hit(cert_pem):
			if invalid(cert_pem):
				lru_cache.set(domain, invalid)
				return
		else:
			cert_pem = redis.get(domain)
			if hit(cert_pem):
				if invalid(cert_pem):
					lru_cache.set(domain, invalid)
					cert_cache.set(domain, invalid)
					return
			else:
				cert_pem = 	upstream_https.get(domain)
				if hit(cert_pem):
					if invalid(cert_pem):
						lru_cache.set(domain, invalid)
						cert_cache.set(domain, invalid)
						return
			if valid(cert_pem)
				lru_cache.set(domain, cert_cdata)
				cert_cache.set(domain, cert_pem)
				cert_cdata = parse(cert_pem)
	if valid(cert_cdata):
		set_ssl_certificate(cert_cdata)
````


### Known problems


# Author

Jonathan Vanasco <jonathan@findmeon.com>

Originally started in https://github.com/aptise/peter_sslers


# Licence

This module is licensed under the MIT License.  See `LICENSE.txt`
