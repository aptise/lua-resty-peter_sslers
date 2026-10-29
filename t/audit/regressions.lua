-- Deterministic backend fault injection; no Redis server or external API needed.
local function run(case)
    local saved_ngx = ngx
    local names = {'cjson.safe', 'resty.lrucache', 'resty.redis', 'ngx.ssl', 'resty.http'}
    local saved = {}
    for _, name in ipairs(names) do saved[name] = package.loaded[name] end
    local cache, api_calls, selected = {}, 0, 0
    local fail_key_write = false
    local payload = {}
    local sni = "test.example.com"
    local deny_lock, throw_api = false, false
    local fail_connect, fail_select, corrupt, outage = false, false, false, false
    local function dict()
        return {
            get = function(_, k) return cache[k] end,
            add = function(_, k, v)
                if deny_lock or cache[k] ~= nil then return nil, 'exists' end
                cache[k] = v; return true
            end,
            set = function(_, k, v)
                if fail_key_write and k == 'test.example.com:k' then return nil, 'no memory' end
                cache[k] = v; return true
            end,
            delete = function(_, k) cache[k] = nil end,
        }
    end
    local null = {}
    ngx = {shared = {cert_cache = dict()}, null = null,
        log = function() end, say = function() end, header = {},
        var = {location = '/expire', request_uri = '/expire/domain/test.example.com'}}
    package.loaded['cjson.safe'] = {null = null, decode = function() return payload end}
    package.loaded['resty.lrucache'] = {new = function()
        local values = {}
        return {get = function(_, k) return values[k] end,
            set = function(_, k, v) values[k] = v end}
    end}
    package.loaded['ngx.ssl'] = {
        server_name = function() return sni end,
        parse_pem_cert = function(v) if v == 'bad' then return nil, 'bad PEM' end return v end,
        parse_pem_priv_key = function(v) return v end,
        clear_certs = function() return true end,
        set_cert = function() return true end,
        set_priv_key = function() return true end,
    }
    local connection = {
        connect = function() if fail_connect then return nil, 'connection refused' end return true end,
        get_reused_times = function() return 0 end,
        select = function() selected = selected + 1; if fail_select then return nil, 'ERR invalid DB' end return true end,
        hmget = function() return { 'key', corrupt and 'bad' or 'cert' } end,
        set_keepalive = function() return true end,
    }
    package.loaded['resty.redis'] = {new = function() return connection end}
    package.loaded['resty.http'] = {new = function() return {
        request_uri = function()
            api_calls = api_calls + 1
            if throw_api then error("injected HTTP exception") end
            if outage then return nil, 'timeout' end
            return {status = 200, body = 'injected response'}
        end,
    } end}
    local ok, err = pcall(function()
        local m = assert(loadfile('lib/resty/peter_sslers.lua'))()
        m.initialize_worker(600, 60, 200)
        if case == 'invalid_sni' then
            for _, name in ipairs({'bad/name', 'bad&name=other', '-bad.example', 'bad..example', string.rep('a', 64) .. '.com'}) do
                sni = name
                m.set_ssl_certificate(nil, 'http://backend', 1)
            end
            assert(api_calls == 0, 'invalid SNI must never reach the backend')
        elseif case == 'canonical_sni' then
            sni = 'TEST.Example.COM.'
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'cert'}, private_key = {pem = 'key'}}}
            m.set_ssl_certificate(nil, 'http://backend', nil)
            assert(cache['test.example.com:pair'], 'DNS case and final dot must share a cache key')
        elseif case == 'lock_busy' then
            deny_lock = true
            m.set_ssl_certificate(nil, 'http://backend', 1)
            assert(api_calls == 0, 'losing atomic lock acquisition must not provision')
        elseif case == 'api_exception' then
            throw_api = true
            m.set_ssl_certificate(nil, 'http://backend', 1)
            assert(cache['test.example.com:autocert_lock'] == nil, 'exception must release autocert lock')
            assert(cache['test.example.com:c'] ~= 'ac', 'exception must clear autocert marker')
        elseif case == 'happy' then
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'cert'}, private_key = {pem = 'key'}}}
            m.set_ssl_certificate(nil, 'http://backend', nil)
            m.set_ssl_certificate(nil, 'http://backend', nil)
            assert(api_calls == 1, 'successful lookup must be cached')
        elseif case == 'write_failure' then
            m.set_cert_sharedcache('test.example.com', {cert = 'old-cert', pkey = 'old-key'})
            fail_key_write = true
            m.set_cert_sharedcache('test.example.com', {cert = 'new-cert', pkey = 'new-key'})
            assert(not (cache['test.example.com:c'] == 'new-cert' and cache['test.example.com:k'] == 'old-key'),
                'failed cache update must not expose a mixed certificate/key pair')
        elseif case == 'expire' then
            m.set_cert_sharedcache('test.example.com', {cert = 'cert', pkey = 'key'})
            m.set_cert_sharedcache('other.example.com', {cert = 'other', pkey = 'other-key'})
            m.expire_ssl_certs()
            assert(cache['test.example.com:c'] == nil and cache['test.example.com:k'] == nil,
                'expiration must remove both certificate parts')
            assert(cache['other.example.com:c'] == 'other', 'expiration must preserve other domains')
        elseif case == 'connect' then
            fail_connect = true
            local con, reason = m.get_redcon()
            assert(con == nil and reason == 'connection refused', 'connection failure must preserve its error')
            assert(selected == 0, 'failed connections must not issue SELECT')
        elseif case == 'select' then
            fail_select = true
            assert(m.get_redcon() == nil, 'failed SELECT must reject the connection')
        elseif case == 'corrupt' then
            corrupt = true
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'cert'}, private_key = {pem = 'key'}}}
            m.set_ssl_certificate(2, 'http://backend', nil)
            assert(api_calls == 1, 'invalid Redis PEM must fall through to API')
            assert(cache['test.example.com:c'] ~= 'bad', 'invalid PEM must not enter shared cache')
        elseif case == 'malformed_retry' or case == 'malformed_retry_autocert' then
            payload = {certificate_signed__latest_multi = {}}
            local autocert = case == 'malformed_retry_autocert' and 1 or nil
            m.set_ssl_certificate(nil, 'http://backend', autocert)
            assert(cache['test.example.com:c'] ~= 'x', 'malformed API result must not become a shared negative entry')
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'cert'}, private_key = {pem = 'key'}}}
            m.set_ssl_certificate(nil, 'http://backend', autocert)
            assert(api_calls == 2, 'malformed API result must not suppress backend recovery')
            assert(cache['test.example.com:pair'], 'recovered API certificate must be cached')
        elseif case == 'absence_cached' then
            payload = {certificate_signed__latest_multi = null, certificate_signed__latest_single = null}
            m.set_ssl_certificate(nil, 'http://backend', nil)
            m.set_ssl_certificate(nil, 'http://backend', nil)
            assert(api_calls == 1, 'explicit certificate absence must still be cached')
        elseif case == 'outage' then
            outage = true
            m.set_ssl_certificate(nil, 'http://backend', nil)
            outage = false
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'cert'}, private_key = {pem = 'key'}}}
            m.set_ssl_certificate(nil, 'http://backend', nil)
            assert(api_calls == 2, 'transport failure must allow a subsequent retry')
        else
            if case == 'scalar' then payload = true
            elseif case == 'nested' then payload = {certificate_signed__latest_multi = {}}
            else payload = {certificate_signed__latest_multi = {}} end
            m.set_ssl_certificate(nil, 'http://backend', case == 'autocert' and 1 or nil)
            assert(cache['test.example.com:c'] ~= 'ac', 'autocert marker must be cleared after malformed response')
        end
    end)
    ngx = saved_ngx
    for _, name in ipairs(names) do package.loaded[name] = saved[name] end
    assert(ok, err)
end
return run
