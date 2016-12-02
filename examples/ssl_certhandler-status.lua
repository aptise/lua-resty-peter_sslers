-- requirements
local ssl_certhandler = require "peter_sslers.ssl_certhandler"

-- alias functions
local ssl_certhandler_status = ssl_certhandler.status_ssl_certs

-- Local cache related
local cert_cache = ngx.shared.cert_cache

ssl_certhandler_status(cert_cache)
