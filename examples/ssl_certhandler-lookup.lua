-- requirements
local ssl_certhandler = require "peter_sslers.ssl_certhandler"

-- alias functions
local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate

local redis_strategy = 1
local fallback_server = 'http://0.0.0.0:7201/.well-known/admin'
local enable_autocert = 1
ssl_certhandler_set(redis_strategy, fallback_server, enable_autocert)
