return function(scenario, http_port)
    local control, shared = ngx.shared.cache_control, ngx.shared.cert_cache
    local worker = ngx.worker.id()
    local function wait_for(predicate)
        local deadline = ngx.now() + 5
        repeat
            assert(not control:get('error'), control:get('error'))
            if predicate() then return end
            ngx.sleep(0.01)
        until ngx.now() >= deadline
        error('cache synchronization timed out: ' .. scenario)
    end
    local function read(path)
        local file = assert(io.open(path))
        local data = file:read('*a'); file:close(); return data
    end
    local first = {cert = read('t/cert/example.com.crt'), pkey = read('t/cert/example.com.key')}
    local second = {cert = read('t/cert/test.example.com.crt'), pkey = read('t/cert/test.example.com.key')}
    local ssl = require 'ngx.ssl'
    local identities, installed, parses = {}, nil, 0
    package.loaded['ngx.ssl'] = {
        server_name = function() return 'test.example.com' end,
        parse_pem_cert = function(pem)
            parses = parses + 1
            local parsed, err = ssl.parse_pem_cert(pem)
            if parsed then identities[tostring(parsed)] = pem == first.cert and 'first' or 'second' end
            return parsed, err
        end,
        parse_pem_priv_key = ssl.parse_pem_priv_key,
        clear_certs = function() return true end,
        set_cert = function(cert) installed = identities[tostring(cert)]; return true end,
        set_priv_key = function() return true end,
    }
    local json = require 'cjson.safe'
    local real_http = require 'resty.http'
    package.loaded['resty.http'] = {new = function() return {request_uri = function()
        control:incr('api_calls', 1, 0)
        if scenario == 'singleflight' then
            control:set('fetch_started', true)
            wait_for(function() return control:get('release_fetch') end)
        end
        if scenario == 'negative' and not control:get('changed') then
            return {status = 200, body = '{"certificate_signed__latest_multi":null,"certificate_signed__latest_single":null}'}
        end
        return {status = 200, body = assert(json.encode({certificate_signed__latest_multi = {
            fullchain = {pem = second.cert}, private_key = {pem = second.pkey}}}))}
    end} end}
    local handler = require 'resty.peter_sslers'
    package.loaded['ngx.ssl'], package.loaded['resty.http'] = ssl, real_http
    handler.initialize_worker(2, scenario == 'ttl' and 0.05 or 1, 200)
    local function lookup() handler.set_ssl_certificate(nil, 'http://injected', nil) end
    local function run()
        if scenario == 'singleflight' then
            if worker == 0 then
                control:set('writer_pid', ngx.worker.pid())
                lookup()
                assert(installed == 'second', 'cold fetch did not install its result')
                assert(parses == 1, 'validated cold result was parsed more than once')
                control:set('writer_done', true)
            else
                wait_for(function() return control:get('fetch_started') end)
                assert(control:get('writer_pid') ~= ngx.worker.pid(), 'misses must use different workers')
                assert(ngx.timer.at(0.05, function() control:set('release_fetch', true) end))
                lookup()
                assert(installed == 'second', 'waiting worker did not receive the fetched result')
                wait_for(function() return control:get('writer_done') end)
                assert(control:get('api_calls') == 1, 'concurrent cold misses fetched the backend twice')
                control:set('reader_done', true)
            end
            return
        end
        if worker == 0 then
            control:set('writer_pid', ngx.worker.pid())
            if scenario == 'negative' then lookup() else assert(handler.set_cert_sharedcache('test.example.com', first)) end
            if scenario == 'storage' then
                assert(not shared:get('test.example.com:pair') and not shared:get('test.example.com:k'),
                    'legacy certificate/key copies remain in shared memory')
                assert(shared:get('test.example.com:c') == true, 'status index must not duplicate PEM')
            end
            control:set('primed', true)
            wait_for(function() return control:get('read_first') end)
            if scenario == 'set' or scenario == 'negative' then
                control:set('changed', true)
                assert(handler.set_cert_sharedcache('test.example.com', second))
            elseif scenario == 'delete' or scenario == 'purge' then
                local suffix = scenario == 'delete' and '/domain/test.example.com' or '/all'
                local response = assert(real_http.new():request_uri('http://127.0.0.1:' .. http_port .. '/expire' .. suffix))
                assert(response.status == 200, 'expiration endpoint failed')
            elseif scenario == 'ttl' then ngx.sleep(0.1) end
            control:set('changed', true)
            control:set('writer_done', true)
        else
            wait_for(function() return control:get('primed') end)
            assert(control:get('writer_pid') ~= ngx.worker.pid(), 'cache test needs distinct worker processes')
            lookup()
            if scenario == 'negative' then
                assert(installed == nil, 'negative cache installed a certificate')
            else
                assert(installed == 'first', 'initial cache value was wrong')
            end
            local first_parses = parses
            control:set('read_first', true)
            wait_for(function() return control:get('writer_done') end)
            lookup()
            if scenario == 'storage' or scenario == 'ttl' then
                assert(installed == 'first')
                if scenario == 'ttl' then assert(parses > first_parses, 'worker TTL was not preserved') end
            else
                assert(installed == 'second', 'worker retained stale certificate or negative cache after invalidation')
            end
            local expected_calls = (scenario == 'delete' or scenario == 'purge' or scenario == 'negative') and 1 or 0
            assert((control:get('api_calls') or 0) == expected_calls, 'unexpected backend lookup count')
            control:set('reader_done', true)
        end
    end
    assert(ngx.timer.at(0, function(premature)
        if premature then return end
        local ok, err = pcall(run)
        if not ok then control:set('error', tostring(err)) end
    end))
end
