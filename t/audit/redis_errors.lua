-- Inject Redis protocol/transport failures without changing the shared audit
-- harness. The live Redis cases separately verify actual WRONGTYPE replies.
return function(case)
    local known = {
        redis_hmget_false_1 = true, redis_hmget_false_2 = true,
        redis_shape_1 = true, redis_shape_2 = true,
        redis_partial_1 = true, redis_partial_2 = true,
        redis_get_false_p = true, redis_get_false_c = true, redis_get_false_i = true,
        redis_get_absent = true, redis_retry_1 = true, redis_retry_2 = true,
        redis_missing_1 = true, redis_missing_2 = true, redis_reuse_error = true,
        redis_pipeline_timeout = true, redis_pipeline_shape = true, redis_pipeline_partial = true,
        redis_pipeline_retry = true,
    }
    assert(known[case], 'unknown Redis regression')
    local saved_ngx = ngx
    local names = {'cjson.safe', 'resty.lrucache', 'resty.redis', 'ngx.ssl', 'resty.http', 'resty.mlcache'}
    local saved = {}
    for _, name in ipairs(names) do saved[name] = package.loaded[name] end
    local null, cache = {}, {}
    local api_calls, redis_calls, pooled, closed = 0, 0, 0, 0
    local fail = true
    local queued
    local strategy = tonumber(case:match('([12])$')) or 1
    ngx = {null = null, log = function() end, header = {}, var = {},
        shared = {cert_cache = {
            get = function(_, k) return cache[k] end,
            set = function(_, k, v) cache[k] = v; return true end,
            delete = function(_, k) cache[k] = nil end,
        }}}
    package.loaded['cjson.safe'] = {null = null, decode = function() return {
        certificate_signed__latest_multi = {fullchain = {pem = 'cert'}, private_key = {pem = 'key'}},
    } end}
    package.loaded['resty.lrucache'] = {new = function()
        local values = {}
        return {delete = function(_, k) values[k] = nil end,
            flush_all = function() for k in pairs(values) do values[k] = nil end end,
            get = function(_, k) return values[k] end,
            set = function(_, k, v) values[k] = v end}
    end}
    package.loaded['ngx.ssl'] = {
        server_name = function() return 'test.example.com' end,
        parse_pem_cert = function(v) assert(type(v) == 'string'); return v end,
        parse_pem_priv_key = function(v) assert(type(v) == 'string'); return v end,
        clear_certs = function() return true end,
        set_cert = function() return true end,
        set_priv_key = function() return true end,
    }
    local function read_part(key)
            local component = case:match('get_false_([pci])')
            if component and key:sub(1, 1) == component then return false, 'WRONGTYPE' end
            if case == 'redis_get_absent' and key:sub(1, 1) == 'p' then return null end
            return 'pem'
    end
    local connection = {
        connect = function() return true end,
        get_reused_times = function()
            if case == 'redis_reuse_error' then return nil, 'closed socket' end
            return 0
        end,
        select = function() return true end,
        hmget = function()
            redis_calls = redis_calls + 1
            if case:match('missing') then return strategy == 1 and {null, null, null} or {null, null} end
            if case:match('partial') then return strategy == 1 and {'cert-id', null, 'chain-id'} or {'key', null} end
            if case:match('hmget_false') then return false, 'WRONGTYPE' end
            if case:match('shape') then return true end
            if case:match('^redis_retry_') and fail then return nil, 'timeout' end
            return strategy == 1 and {'cert-id', 'key-id', 'chain-id'} or {'key', 'cert'}
        end,
        init_pipeline = function() queued = {} end,
        get = function(_, key)
            if queued then queued[#queued + 1] = key; return end
            return read_part(key)
        end,
        commit_pipeline = function()
            local pending = queued
            queued = nil
            if case == 'redis_pipeline_timeout' or (case == 'redis_pipeline_retry' and fail) then return nil, 'timeout' end
            if case == 'redis_pipeline_shape' then return true end
            if case == 'redis_pipeline_partial' then return {'pem'} end
            local replies = {}
            for index, key in ipairs(pending) do
                local value, err = read_part(key)
                if value == nil and err then return nil, err end
                if value == false then replies[index] = {false, err} else replies[index] = value end
            end
            return replies
        end,
        set_keepalive = function() pooled = pooled + 1; return true end,
        close = function() closed = closed + 1; return true end,
    }
    package.loaded['resty.redis'] = {new = function() return connection end}
    package.loaded['resty.http'] = {new = function() return {request_uri = function()
        api_calls = api_calls + 1
        return {status = 200, body = 'injected response'}
    end} end}
    package.loaded['resty.mlcache'] = assert(loadfile('t/lib/mlcache_fake.lua'))()
    local ok, err = pcall(function()
        local handler = assert(loadfile('lib/resty/peter_sslers.lua'))()
        handler.initialize_worker(600, 60, 200)
        if case == 'redis_reuse_error' then
            local con, reason = handler.get_redcon()
            assert(con == nil and reason == 'closed socket', 'reuse-state error must be preserved')
            assert(closed == 1, 'failed reuse-state check must close the connection')
        elseif case:match('retry') then
            handler.set_ssl_certificate(strategy, nil, nil)
            assert(cache['test.example.com:c'] ~= 'x', 'Redis timeout must not create a negative entry')
            fail = false
            handler.set_ssl_certificate(strategy, nil, nil)
            assert(redis_calls == 2 and cache['test.example.com:pair'], 'Redis must recover on the next lookup')
            assert(closed == 1 and pooled == 1, 'only healthy connections should be pooled')
        elseif case:match('missing') then
            handler.set_ssl_certificate(strategy, nil, nil)
            handler.set_ssl_certificate(strategy, nil, nil)
            assert(redis_calls == 1 and cache['test.example.com:c'] == 'x', 'missing Redis domain must still be negatively cached')
        else
            handler.set_ssl_certificate(strategy, 'http://backend', nil)
            assert(api_calls == 1, 'Redis command failure must reach the API')
            assert(cache['test.example.com:pair'], 'API certificate must be cached after Redis failure')
            assert(closed == 1 and pooled == 0, 'failed Redis query must close its connection')
        end
    end)
    ngx = saved_ngx
    for _, name in ipairs(names) do package.loaded[name] = saved[name] end
    assert(ok, err)
end
