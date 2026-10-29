return function(directory)
    local function read(path)
        local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
    end
    local json = require 'cjson.safe'
    local ports = assert(json.decode(read(directory .. '/ports.json')))
    local http = require 'resty.http'
    local function control(action)
        local response = assert(http.new():request_uri('http://127.0.0.1:' .. ports.http .. '/retry/' .. action,
            {headers = {Authorization = 'Basic ' .. ngx.encode_base64('audit:test-password')}}))
        assert(response.status == 200)
        return assert(json.decode(response.body))
    end
    local sni, installed = 'outage.example.com', 0
    local ssl = require 'ngx.ssl'
    package.loaded['ngx.ssl'] = {
        server_name = function() return sni end,
        parse_pem_cert = ssl.parse_pem_cert, parse_pem_priv_key = ssl.parse_pem_priv_key,
        clear_certs = function() return true end,
        set_cert = function() installed = installed + 1; return true end,
        set_priv_key = function() return true end,
    }
    local handler = assert(loadfile('lib/resty/peter_sslers.lua'))()
    package.loaded['ngx.ssl'] = ssl
    handler.initialize_worker(600, 60, 200)
    handler.api_update_defaults({username = 'audit', password = 'test-password', retry_backoff = 1, timeout = 1000})
    local function lookup(name)
        sni = name
        handler.set_ssl_certificate(nil, 'http://127.0.0.1:' .. ports.http .. '/retry/backend', nil)
    end
    control('reset')
    assert(handler.set_cert_sharedcache('cached.example.com', {
        cert = read('t/cert/test.example.com.crt'), pkey = read('t/cert/test.example.com.key')}))
    lookup('outage.example.com')
    lookup('another.example.com')
    assert(installed == 0 and control('stats').calls == 1, 'real HTTP outage was retried during cooldown')
    local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache'))
    assert(not inspector:peek('outage.example.com') and not inspector:peek('another.example.com'),
        'outage produced cached certificate absence')
    lookup('cached.example.com')
    assert(installed == 1 and control('stats').calls == 1, 'cooldown blocked cached certificates')
    control('recover')
    lookup('outage.example.com')
    assert(installed == 1 and control('stats').calls == 1, 'cooldown expired too early')
    ngx.sleep(1.1)
    lookup('outage.example.com')
    assert(installed == 2 and control('stats').calls == 2, 'HTTP recovery was blocked after cooldown')
    lookup('fresh.example.com')
    assert(installed == 3 and control('stats').calls == 3, 'healthy API remained throttled')
end
