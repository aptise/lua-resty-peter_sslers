-- Real PEM/key validation with controlled TLS installation failures.
return function(case)
    local function read(path)
        local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
    end
    local cert, key = read('t/cert/test.example.com.crt'), read('t/cert/test.example.com.key')
    local other_key = read('t/cert/example.com.key')
    local ssl, saved_exit = require('ngx.ssl'), ngx.exit
    local events, calls, validations = {}, 0, 0
    local saved_x509 = require 'resty.openssl.x509'
    package.loaded['resty.openssl.x509'] = {new = function(...)
        validations = validations + 1
        return saved_x509.new(...)
    end}
    local function event(name)
        events[#events + 1] = name
        if case == name .. '_failure' then return nil, 'injected installation failure' end
        return true
    end
    package.loaded['ngx.ssl'] = {
        server_name = function() return 'test.example.com' end,
        parse_pem_cert = ssl.parse_pem_cert, parse_pem_priv_key = ssl.parse_pem_priv_key,
        clear_certs = function() return event('clear') end,
        set_cert = function() return event('cert') end,
        set_priv_key = function() return event('key') end,
    }
    ngx.exit = function(status) events[#events + 1] = 'exit'; assert(status == ngx.ERROR) end
    local saved_http, saved_redis = package.loaded['resty.http'], package.loaded['resty.redis']
    package.loaded['resty.http'] = {new = function() return {request_uri = function()
        calls = calls + 1
        local candidate_cert = case == 'bad_cert' and 'bad' or cert
        if case == 'chain_mismatch' then candidate_cert = cert .. read('t/cert/example.com.crt') end
        local candidate_key = case == 'bad_key' and 'bad' or ((case == 'mismatch' or case == 'chain_mismatch') and other_key or key)
        return {status = 200, body = assert(require('cjson.safe').encode({certificate_signed__latest_multi = {
            fullchain = {pem = candidate_cert}, private_key = {pem = candidate_key}}}))}
    end} end}
    package.loaded['resty.redis'] = {new = function() return {
        connect = function() return true end, get_reused_times = function() return 0 end,
        select = function() return true end, hmget = function() return {other_key, cert} end,
        set_keepalive = function() return true end, close = function() return true end,
    } end}
    local ok, err = pcall(function()
        local handler = assert(loadfile('lib/resty/peter_sslers.lua'))()
        handler.initialize_worker(600, 60, 200)
        if case == 'shared_mismatch' then
            local reused = {cert = 'old certificate', pkey = 'old key'}
            handler.certificate_pairing_pem_to_cdata({cert = cert, pkey = other_key}, reused)
            assert(not reused.cert and not reused.pkey, 'validation failure retained a previous output pair')
            local stored = handler.set_cert_sharedcache('test.example.com', {cert = cert, pkey = other_key})
            assert(not stored, 'shared-cache setter accepted a mismatched key')
            local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache'))
            assert(inspector:peek('test.example.com') == nil, 'rejected shared pair remained cached')
        else
            handler.set_ssl_certificate(case == 'redis_fallback' and 2 or nil, 'http://installation-fixture', nil)
        end
        local actual = table.concat(events, ',')
        if case == 'mismatch' or case == 'chain_mismatch' or case == 'shared_mismatch'
            or case == 'bad_cert' or case == 'bad_key' then
            assert(actual == '', 'invalid pair touched TLS credentials: ' .. actual)
            local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache'))
            assert(inspector:peek('test.example.com') == nil, 'invalid pair created cached certificate/absence')
        elseif case == 'clear_failure' then
            assert(actual == 'clear,exit', 'clear failure did not stop installation: ' .. actual)
        elseif case == 'cert_failure' then
            assert(actual == 'clear,cert,exit', 'certificate failure did not abort: ' .. actual)
        elseif case == 'key_failure' then
            assert(actual == 'clear,cert,key,exit', 'key failure did not abort: ' .. actual)
        else
            assert(actual == 'clear,cert,key', 'valid pair installation order: ' .. actual)
            assert(calls == 1, 'mismatched datastore pair did not use API fallback')
            if case == 'success' then
                handler.set_ssl_certificate(nil, 'http://installation-fixture', nil)
                assert(validations == 1 and calls == 1, 'L1 hit repeated backend/key validation')
                assert(table.concat(events, ',') == 'clear,cert,key,clear,cert,key')
            end
        end
    end)
    package.loaded['resty.openssl.x509'] = saved_x509
    package.loaded['ngx.ssl'], ngx.exit = ssl, saved_exit
    package.loaded['resty.http'], package.loaded['resty.redis'] = saved_http, saved_redis
    assert(ok, err)
end
