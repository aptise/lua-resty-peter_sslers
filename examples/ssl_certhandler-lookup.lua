-- requirements
local ssl_certhandler = require "peter_sslers.ssl_certhandler"

-- alias functions
local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate

-- Local cache related
local cert_cache = ngx.shared.cert_cache
local cert_cache_duration = 7200 -- 2 hours

local prime_version = 1
local fallback_server = 'http://0.0.0.0:6543'
ssl_certhandler_set(cert_cache, cert_cache_duration, prime_version, fallback_server)
