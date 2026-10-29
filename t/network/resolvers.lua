return function(case, directory)
    local function read(path)
        local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
    end
    local ports = assert(require('cjson.safe').decode(read(directory .. '/ports.json')))
    local host = (case == 'no_resolver' and 'nx' or case) .. '-' .. ngx.worker.pid() .. '.test'
    local url = 'http://' .. host .. ':' .. ports.http .. '/basic'
    local query_strategy
    if case == 'redis_failover' then
        host = 'nx-' .. ngx.worker.pid() .. '.test'
        url = 'http://127.0.0.1:' .. ports.http .. '/basic'
        query_strategy = 1
    end
    -- TLS phase accessors/setters are injected. DNS, HTTP/Redis transports,
    -- shared caching, and PEM parsing are real; TLS handshakes are covered by
    -- the certificate-serving and shared-memory-pressure tests.
    local ssl = require 'ngx.ssl'
    local installed = 0
    package.loaded['ngx.ssl'] = {
        server_name = function() return 'test.example.com' end,
        parse_pem_cert = ssl.parse_pem_cert,
        parse_pem_priv_key = ssl.parse_pem_priv_key,
        clear_certs = function() return true end,
        set_cert = function() installed = installed + 1; return true end,
        set_priv_key = function() return true end,
    }
    local configured = assert(loadfile('lib/resty/peter_sslers.lua'))()
    package.loaded['ngx.ssl'] = ssl
    configured.initialize_worker(600, 60, 200)
    configured.api_update_defaults({username = 'audit', password = 'test-password', timeout = 1000})
    if query_strategy then configured.valkey_update_defaults(host, ports.plain, 9, {timeout = 1000}) end
    configured.set_ssl_certificate(query_strategy, url, nil)
    local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache'))
    local remaining = inspector:peek('test.example.com')
    local stats = assert(require('resty.http').new():request_uri(
        'http://127.0.0.1:' .. ports.http .. '/dns/stats?name=' .. host,
        {headers = {Authorization = 'Basic ' .. ngx.encode_base64('audit:test-password')}}))
    local queries = assert(require('cjson.safe').decode(stats.body)).queries
    assert(case == 'no_resolver' and queries == 0 or case ~= 'no_resolver' and queries > 0,
        'test did not exercise the configured DNS behavior')
    if case == 'redis_failover' then
        assert(installed == 1 and remaining, 'failed datastore DNS did not fall through to API')
        return
    end
    assert(installed == 0 and remaining == nil, 'DNS failure installed or negatively cached credentials')
    if case == 'recover' then
        local response = assert(require('resty.http').new():request_uri(
            'http://127.0.0.1:' .. ports.http .. '/dns/recover?name=' .. host,
            {headers = {Authorization = 'Basic ' .. ngx.encode_base64('audit:test-password')}}))
        assert(response.status == 204)
        ngx.sleep(1.1) -- resolver valid=1s bounds its own negative cache.
        configured.set_ssl_certificate(nil, url, nil)
        assert(installed == 1 and inspector:peek('test.example.com'), 'DNS recovery was blocked by certificate negative caching')
    end
end
