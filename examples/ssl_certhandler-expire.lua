-- requirements
local ssl_certhandler = require "resty.peter_sslers"

-- alias functions
local ssl_certhandler_expire = ssl_certhandler.expire_ssl_certs
ssl_certhandler_expire()
