-- requirements
local ssl_certhandler = require "peter_sslers.ssl_certhandler"

-- alias functions
local ssl_certhandler_set = ssl_certhandler.set_ssl_certificate

local prime_version = 1
local fallback_server = 'http://0.0.0.0:6543'
ssl_certhandler_set(prime_version, fallback_server)
