-- Exercise real shared dictionaries in two workers. Only TLS phase accessors
-- and the HTTP transport are replaced; PEM parsing and worker LRUs are real.
return function(scenario, http_port)
    local control = ngx.shared.audit_control
    local cache = ngx.shared.cert_cache
    local worker = ngx.worker.id()
    local cancelled = scenario == 'expired' or scenario == 'flushed'
    local replaced = scenario == 'replaced' or scenario == 'exception'
        or scenario == 'evicted' or scenario == 'flushed_replaced'
    local real_http = require 'resty.http'
    local function wait_for(predicate)
        local deadline = ngx.now() + 5
        repeat
            assert(not control:get('error'), control:get('error'))
            if predicate() then return end
            ngx.sleep(0.01)
        until ngx.now() >= deadline
        error('timed out in ' .. scenario .. ' worker ' .. worker)
    end
    local function read(path)
        local file = assert(io.open(path, 'r'))
        local value = file:read('*a')
        file:close()
        return value
    end
    local old_cert = read('t/cert/example.com.crt')
    local old_key = read('t/cert/example.com.key')
    local new_cert = read('t/cert/test.example.com.crt')
    local new_key = read('t/cert/test.example.com.key')
    local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache'))
    local function packed_pair()
        local _, err, value = inspector:peek('test.example.com')
        assert(not err, err)
        return value
    end
    local lock_key = 'test.example.com:autocert_lock'
    local marker_key = 'test.example.com:c'
    local function new_pair_present()
        return packed_pair() == new_cert .. string.char(0) .. new_key
    end
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
    local json = require 'cjson.safe'
    package.loaded['resty.http'] = {new = function() return {
        request_uri = function()
            assert(control:incr('api_calls', 1, 0))
            local cert, key
            if worker == 0 then
                control:set('owner_pid', ngx.worker.pid())
                control:set('first_started', true)
                if scenario == 'pending' or cancelled then
                    wait_for(function() return control:get('release_first') end)
                elseif scenario == 'new_certificate' then
                    wait_for(function() return control:get('replacement_done') end)
                else
                    wait_for(function() return control:get('second_started') end)
                end
                if scenario == 'exception' then error('late HTTP exception') end
                cert, key = old_cert, old_key
            else
                control:set('replacement_token', cache:get(lock_key))
                control:set('second_started', true)
                if replaced then
                    wait_for(function() return control:get('owner_done') end)
                end
                cert, key = new_cert, new_key
            end
            return {status = 200, body = assert(json.encode({
                certificate_signed__latest_multi = {fullchain = {pem = cert}, private_key = {pem = key}},
            }))}
        end,
    } end}
    local handler = require 'resty.peter_sslers'
    package.loaded['ngx.ssl'] = ssl
    handler.initialize_worker((scenario == 'pending' or scenario == 'evicted'
        or scenario:match('^flushed')) and 60 or 0.3, 0.1, 200)
    local function lookup()
        handler.set_ssl_certificate(nil, 'http://injected-api', 1)
    end
    local function run()
        if worker == 0 then
            lookup()
            if replaced then
                assert(cache:get(lock_key) == control:get('replacement_token'), 'late owner deleted replacement lock')
                assert(cache:get(marker_key) == 'ac', 'late owner removed replacement marker')
                assert(installed == 0, 'late owner installed obsolete credentials')
            elseif cancelled then
                assert(not packed_pair(), 'expired owner repopulated the cache')
                assert(installed == 0, 'expired owner installed obsolete credentials')
            elseif scenario == 'new_certificate' then
                assert(new_pair_present(), 'late owner overwrote newer certificate')
                assert(installed == 0, 'late owner installed obsolete credentials')
            else
                assert(installed == 1, 'owner did not install its certificate')
            end
            control:set('owner_done', true)
        else
            wait_for(function() return control:get('first_started') end)
            assert(control:get('owner_pid') ~= ngx.worker.pid(), 'test must use distinct worker processes')
            control:set('contender_pid', ngx.worker.pid())
            if scenario == 'pending' then
                lookup()
                assert(control:get('api_calls') == 1, 'contender issued a duplicate API call')
                assert(installed == 0, 'pending contender should retain the default certificate')
                control:set('release_first', true)
                wait_for(function() return control:get('owner_done') end)
                lookup()
                assert(installed == 1, 'contender could not read the shared certificate')
            else
                if scenario:match('^flushed') then
                    local response = assert(real_http.new():request_uri(
                        'http://127.0.0.1:' .. http_port .. '/expire/all'))
                    assert(response.status == 200, 'flush endpoint failed')
                    assert(cache:get(lock_key) == nil, 'flush retained the old lease')
                elseif scenario == 'evicted' then
                    local forcible = false
                    for index = 1, 64 do
                        local ok, err, evicted = cache:set('lease-pressure-' .. index, string.rep('x', 65536))
                        assert(ok, err)
                        forcible = forcible or evicted
                    end
                    assert(forcible and cache:get(lock_key) == nil, 'test did not evict the active lease')
                else
                    wait_for(function() return cache:get(lock_key) == nil end)
                end
                if cancelled then
                    control:set('release_first', true)
                else
                    lookup()
                    assert(new_pair_present(), 'replacement certificate was not published')
                    control:set('replacement_done', true)
                end
                wait_for(function() return control:get('owner_done') end)
            end
            control:set('contender_done', true)
        end
    end
    assert(ngx.timer.at(0, function(premature)
        if premature then return end
        local ok, err = pcall(run)
        if not ok then control:set('error', tostring(err)) end
    end))
end
