# lua-resty-peter_sslers

Lua support for https://github.com/aptise/peter_sslers Certificate Manager in
OpenResty

# Status

This package has been used in production since 2016

The `0.4.0` release requires `peter_sslers >= 0.4.0`

Earlier releases require `peter_sslers < 0.4.0`

# Installation

one line...

    sudo opm install aptise/lua-resty-peter_sslers

upgrading?

    sudo opm upgrade aptise/lua-resty-peter_sslers


## Synopsis

`lua-resty-peter_sslers` is a library that can be used in an OpenResty/Nginx
environment to dynamically serve the correct SSL certificate for a given domain.

Working alongside https://github.com/aptise/peter_sslers , this package will
load existing certificates or perform an "autocert" to provision a new one.

It supports both the prime cache types 1 & 2 of `peter_sslers`

It supports "autocert" functionality with `peter_sslers`

It is implemented as a library with some example scripts to invoke it.

* core library
  * `ssl_certhandler.lua`
* examples
  * `ssl_certhandler-lookup.lua`
  * `ssl_certhandler-expire.lua`
  * `ssl_certhandler-status.lua`

The `-lookup.lua`, `-expire.lua`,  `-status.lua` scripts can be copied into a
block.

The library is hardcoded to use db9 in redis.  if you want another option, edit
or PR a fix on the line that looks like:

	ngx.log(ngx.ERR, "changing to db 9: ", times)
	redcon:select(9)

Redis is NOT required, but recommended.  Instead you can failover to directly
query a peter_sslers pyramid instance.

### To Disable Redis

invoke `ssl_certhandler_set` with `redis_strategy` as `nil`, instead of `1` or
`2`. Simple!

To use the Peter SSlers Pyramid fallback, the following library is used:

* lua-resty-http https://github.com/pintsized/lua-resty-http

Hits and misses from the fallback API will be cached in the shared cache dict.
If you need to remove values, you will need to restart the server OR use one of
the Nginx/lua examples for cache clearing.  Fallback API requests will notify
the Pyramid app that the request should have write-through cache behavior.

### Caching Note

In order to maximize performance there are 2 layers of caching WITHIN
Nginx/OpenResty:

* certificates are cached in a LRU cache within a given worker in the native
  CDATA format for `ssl_certhandler.lru_cache_duration` seconds (default 60)
* certificates are cached across all workers in PEM format for
  `ssl_certhandler.cert_cache_duration` seconds (default 600)

These values can be adjusted.

Why?

The Nginx shared dict can easily have values queried
flushed/expired/overwritten, however it can only store PEM certificates (not
the cdata pointers), so the certificates need to be repeatedly parsed.

The LRU cache can hold the cdata pointers, but implementation details of
Nginx/OpenResty do not allow easy query & manipulation of the cache.
Messaging between all the workers for overwriting/expiry would be a large task
too.

An easy way to handle deployment concerns is to use a timeout on the LRU cache
that is long-enough to perform well under load, but short-enough to allow for
changes in the shared-dict to propagate.


## Usage

Make sure your Nginx contains:

````
    server {
		# initialize the cert_cache to a size
		# it will be accessed via `nginx.shared.cert_cache`
		lua_shared_dict  cert_cache 100k;
		lua_code_cache  on;
		init_by_lua_block {
			require "resty.core"
			local ssl_certhandler = require "peter_sslers.ssl_certhandler"
			ssl_certhandler.initialize()
		}
		init_worker_by_lua_block {
			require "resty.core"
			local ssl_certhandler = require "peter_sslers.ssl_certhandler"
			-- cert_cache_duration, lru_cache_duration, lru_maxitems
			ssl_certhandler.initialize_worker(90, 30, 200)
		}
	}
````

* `initialize` currently does nothing.
* `initialize_worker` accepts three arguments:
  * `cert_cache_duration` seconds for PEM cache in ngx.shared.DICT
  * `lru_cache_duration` seconds for LRU cache of cdata pointer in worker
  * `lru_maxitems` max number of items for LRU cache of cdata pointer in worker

Then implement the example routes

Due to an implementation detail of lua/luajit, the examples below must be
implemented in a block/file and can not be "require(/path/to/example)".
This is because of how the Redis connection is instantiated.

see:

* https://github.com/openresty/lua-resty-redis/issues/33
* https://github.com/openresty/lua-nginx-module/issues/376

### ssl_certhandler.lua

Core library.  Exposes several functions.


### examples/ssl_certhandler-lookup.lua

This is very simple, it merely specfies a cache, duration, and redis_strategy

Invoked within Nginx...

```
    server {
        listen 443 default_server;
        ...
        // nginx must have a default configured
        ssl_certificate /path/to/default/fullchain.pem;
        ssl_certificate_key /path/to/default/privkey.pem;
		ssl_certificate_by_lua_block  {
		}
```

### examples/ssl_certhandler-expire.lua

The Nginx shared memory cache persists across configuration reloads.
Servers must be fully restarted to clear memory.

The workaround?  API endpoints to "flush" the cache or expire certain
keys(domains).

A simple example is provided with `peter_sslers.ssl_certhandler-expire`,
which can be invoked within Nginx as-is rather easily:

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
** Flushes the entire Nginx certificate cache
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

            local redis_strategy = 1
            local fallback_server = 'http://0.0.0.0:6543/.well-known/admin'
            local enable_autocert = 1
            ssl_certhandler_set(redis_strategy, fallback_server, enable_autocert)
        }
````


### fully configured example

a fully configured example is available in the main peter_sslers repo: https://github.com/aptise/peter_sslers/blob/master/tools/nginx_conf/enabled.conf

### Details

This approach makes aggressive use of caching in the Nginx workers (via worker
lru and a shared dict) and Redis; caching both hits and misses.

The Nginx worker dicts are shared across reloads (`kill -HUP {PID}`); so if a
bad value gets in there you must restart or wait for the timeout.

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
				if autocert_enabled:
					cert_pem = 	upstream_https.get(domain)  # autocert
				else:
					cert_pem = 	upstream_https.get(domain)  # query
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


### Integration/Debugging HowTo

Various levels of information are sent to the following debug levels of Nginx.
Changing the Nginx debug level will expose more data

* ERR
* NOTICE
* DEBUG

Notice how a worker is initialized:

	-- cert_cache_duration, lru_cache_duration, lru_maxitems
	ssl_certhandler.initialize_worker(90, 30, 100)
	
For debugging you may want to lower these to shorten the LRU cache to a
negligible number

	ssl_certhandler.initialize_worker(5, 1, 100)
	
The "/status" and "/expire" routes only show information in the shared cache --
information is cached into each worker's own LRU cache and is not available to
these routes.  If "/expire" is used, a domain will be removed from the shared
cache and "/status" route... but may still be in a worker's LRU.


Check the status:

	curl -k https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/status

expire

	curl -k https://peter:sslers@127.0.0.1/.peter_sslers/nginx/shared_cache/expire
	
	
### Tests

#### Luacheck

The tests in `test.yml` disable unused variables:

    - run: luacheck lib --no-unused

To do local tests

	luarocks install luacheck
	luacheck lib

#### Test::Nginx

Upgrade CPAN

	cpan
	upgrade

Install cpanm

	cpan App::cpanminus

Install the test harness

	cpanm -q -n Test::Nginx


Where is your openresty? Make sure it's in the path

	export PATH=/usr/local/openresty/nginx/sbin:$PATH
	export PATH=/usr/local/bin/:$PATH

Run the test(s)

	/usr/bin/prove -I../test-nginx/lib -r t/



### Known problems


# Author

Jonathan Vanasco <jonathan@findmeon.com>

Originally started in https://github.com/aptise/peter_sslers

The tests and github actions are copied or inspired by the excellent lua-resty-http
module https://github.com/ledgetech/lua-resty-http by James Hurst and the openresty
test suites.


# Licence

This module is licensed under the MIT License.  See `LICENSE.txt`
