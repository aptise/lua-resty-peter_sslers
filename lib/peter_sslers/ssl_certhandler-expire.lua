-- requirements
local ssl_certhandler = require "peter_sslers.ssl_certhandler"

-- alias functions
local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs

-- Local cache related
local cert_cache = ngx.shared.cert_cache

ssl_certhandler_expire(cert_cache)