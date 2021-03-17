-- requirements
local ssl_certhandler = require "resty.peter_sslers"

-- alias functions
local ssl_certhandler_status = ssl_certhandler.status_ssl_certs
ssl_certhandler_status()
