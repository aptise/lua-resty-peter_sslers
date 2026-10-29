-- Real worker/shared cache coordination, with controlled backend availability.
return function(scenario)
    local control, cache = ngx.shared.retry_control, ngx.shared.cert_cache
    local worker = ngx.worker.id()
    local function read(path)
        local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
    end
    local cert, key = read('t/cert/test.example.com.crt'), read('t/cert/test.example.com.key')
    local sni = 'request-' .. worker .. '.example.com'
    local installed = 0
    local ssl = require 'ngx.ssl'
    package.loaded['ngx.ssl'] = {
        server_name = function() return sni end,
        parse_pem_cert = ssl.parse_pem_cert, parse_pem_priv_key = ssl.parse_pem_priv_key,
        clear_certs = function() return true end,
        set_cert = function() installed = installed + 1; return true end,
        set_priv_key = function() return true end,
    }
    local json = require 'cjson.safe'
    package.loaded['resty.http'] = {new = function() return {request_uri = function()
        control:incr('api_calls', 1, 0)
        if scenario == 'success_reset' then
            if worker == 0 then
                control:set('first_fetch', true)
                local deadline = ngx.now() + 5
                while not control:get('failed') do
                    assert(ngx.now() < deadline, 'success-reset synchronization timed out')
                    ngx.sleep(0.01)
                end
                control:set('healthy', true)
            elseif not control:get('first_success') then
                return nil, 'concurrent controlled failure'
            end
        end
        if scenario == 'domain_failure' and worker == 0 then
            return {status = 200, body = '{"certificate_signed__latest_multi":{"fullchain":{"pem":"bad"},"private_key":{"pem":"bad"}}}'}
        end
        if scenario == 'absence' then
            return {status = 200, body = '{"certificate_signed__latest_multi":null,"certificate_signed__latest_single":null}'}
        end
        if not control:get('healthy') and scenario ~= 'fallback' and scenario ~= 'domain_failure' then
            if scenario == 'exception' then error('controlled transport exception') end
            return nil, 'controlled outage'
        end
        return {status = 200, body = assert(json.encode({certificate_signed__latest_multi = {
            fullchain = {pem = cert}, private_key = {pem = key}}}))}
    end} end}
    package.loaded['resty.redis'] = {new = function() return {
        connect = function()
            control:incr('redis_calls', 1, 0)
            if not control:get('healthy') then return nil, 'controlled outage' end
            return true
        end,
        get_reused_times = function() return 0 end,
        select = function() return true end,
        hmget = function() return {key, cert} end,
        set_keepalive = function() return true end,
        close = function() return true end,
    } end}
    local handler = require 'resty.peter_sslers'
    package.loaded['ngx.ssl'] = ssl
    handler.initialize_worker(600, 60, 200)
    local function lookup()
        local strategy = (scenario == 'redis' or scenario == 'fallback') and 2 or nil
        local api = scenario ~= 'redis' and 'http://retry-fixture' or nil
        handler.set_ssl_certificate(strategy, api, scenario == 'autocert' and 1 or nil)
    end
    local function wait_for(predicate)
        local deadline = ngx.now() + 5
        repeat
            assert(not control:get('error'), control:get('error'))
            if predicate() then return end
            ngx.sleep(0.01)
        until ngx.now() >= deadline
        error('retry worker synchronization timed out')
    end
    local function run()
        if scenario == 'success_reset' then
            if worker == 0 then
                lookup()
                assert(installed == 1)
                control:set('first_success', true)
                wait_for(function() return control:get('reader_done') end)
                control:set('writer_done', true)
            else
                wait_for(function() return control:get('first_fetch') end)
                lookup()
                assert(installed == 0 and control:get('api_calls') == 2)
                control:set('failed', true)
                wait_for(function() return control:get('first_success') end)
                sni = 'third.example.com'
                lookup()
                assert(installed == 1 and control:get('api_calls') == 3, 'successful request did not clear concurrent cooldown')
                control:set('reader_done', true)
            end
            return
        end
        if scenario == 'disabled' then handler.api_update_defaults({retry_backoff = 0}) end
        if scenario == 'identity' then
            handler.api_update_defaults({authorization = 'Bearer old-test-secret', retry_backoff = 1})
        end
        if worker == 0 then
            control:set('writer_pid', ngx.worker.pid())
            lookup()
            if scenario == 'absence' then lookup() end
            control:set('first_done', true)
            wait_for(function() return control:get('reader_done') end)
            control:set('writer_done', true)
        else
            wait_for(function() return control:get('first_done') end)
            assert(control:get('writer_pid') ~= ngx.worker.pid(), 'retry test needs distinct worker processes')
            if scenario == 'cached' then
                assert(handler.set_cert_sharedcache(sni, {cert = cert, pkey = key}))
            end
            lookup()
            local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache'))
            if scenario == 'absence' or scenario == 'disabled' then
                assert(control:get('api_calls') == 2, 'explicit absence or disabled backoff suppressed another domain')
            elseif scenario == 'cached' then
                assert(installed == 1 and control:get('api_calls') == 1, 'cooldown blocked cached credentials')
            elseif scenario == 'domain_failure' then
                assert(installed == 1 and control:get('api_calls') == 2, 'one bad domain suppressed healthy domains')
                sni = 'request-0.example.com'
                lookup()
                assert(installed == 1 and control:get('api_calls') == 2, 'corrupt domain was not cooled down across workers')
            elseif scenario == 'fallback' then
                assert(installed == 1 and control:get('redis_calls') == 1 and control:get('api_calls') == 2,
                    'failed datastore was retried or healthy API fallback was blocked')
            else
                local counter = scenario == 'redis' and 'redis_calls' or 'api_calls'
                assert(control:get(counter) == 1, 'other worker retried a backend during cooldown')
                assert(installed == 0 and inspector:peek(sni) == nil, 'outage created certificate or negative state')
                control:set('healthy', true)
                if scenario == 'identity' then
                    handler.api_update_defaults({authorization = 'Bearer new-test-secret', retry_backoff = 1})
                else
                    ngx.sleep(1.1)
                end
                lookup()
                assert(installed == 1 and control:get(counter) == 2, 'backend did not recover after cooldown')
                for _, name in ipairs(cache:get_keys(0)) do
                    assert(not name:find('test-secret', 1, true), 'retry identity leaked credentials')
                end
            end
            control:set('reader_done', true)
        end
    end
    assert(ngx.timer.at(0, function(premature)
        if premature then return end
        local ok, err = pcall(run)
        if not ok then control:set('error', tostring(err)) end
    end))
end
