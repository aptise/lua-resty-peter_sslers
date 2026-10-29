-- Deterministic backend fault injection; no Redis server or external API needed.
local function run(case)
    local saved_ngx = ngx
    local names = {'cjson.safe', 'resty.lrucache', 'resty.redis', 'ngx.ssl', 'resty.http', 'resty.mlcache',
        'resty.openssl.x509', 'resty.openssl.pkey'}
    local saved = {}
    for _, name in ipairs(names) do saved[name] = package.loaded[name] end
    local cache, api_calls, selected = {}, 0, 0
    local fail_key_write = false
    local payload = {}
    local sni = "test.example.com"
    local deny_lock, throw_api = false, false
    local on_request
    local fail_connect, fail_select, corrupt, outage = false, false, false, false
    local function dict()
        return {
            get = function(_, k) return cache[k] end,
            add = function(_, k, v)
                if deny_lock or cache[k] ~= nil then return nil, 'exists' end
                cache[k] = v; return true
            end,
            set = function(_, k, v)
                if fail_key_write and k == 'test.example.com:pair' then return nil, 'no memory' end
                cache[k] = v; return true
            end,
            delete = function(_, k) cache[k] = nil end,
        }
    end
    local null = {}
    ngx = {shared = {cert_cache = dict()}, null = null,
        worker = {pid = function() return 1234 end},
        log = function() end, say = function() end, header = {},
        var = {location = '/expire', request_uri = '/expire/domain/test.example.com'}}
    package.loaded['cjson.safe'] = {null = null, decode = function() return payload end}
    package.loaded['resty.lrucache'] = {new = function()
        local values = {}
        return {delete = function(_, k) values[k] = nil end,
            flush_all = function() for k in pairs(values) do values[k] = nil end end,
            get = function(_, k) return values[k] end,
            set = function(_, k, v) values[k] = v end}
    end}
    package.loaded['resty.openssl.x509'] = {new = function()
        return {check_private_key = function() return true end}
    end}
    package.loaded['resty.openssl.pkey'] = {new = function() return {} end}
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
            if on_request then on_request() end
            if throw_api then error("injected HTTP exception") end
            if outage then return nil, 'timeout' end
            return {status = 200, body = 'injected response'}
        end,
    } end}
    package.loaded['resty.mlcache'] = assert(loadfile('t/lib/mlcache_fake.lua'))()
    local ok, err = pcall(function()
        local m = assert(loadfile('lib/resty/peter_sslers.lua'))()
        m.initialize_worker(600, 60, 200)
        m.redis_update_defaults('127.0.0.1', 6379, 9, {retry_backoff = 0})
        m.api_update_defaults({retry_backoff = 0})
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
        elseif case == 'lease_replaced' or case == 'lease_exception' then
            on_request = function()
                cache['test.example.com:autocert_lock'] = 'new-owner'
                cache['test.example.com:c'], cache['test.example.com:k'] = 'ac', 'ac'
            end
            throw_api = case == 'lease_exception'
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'old-cert'}, private_key = {pem = 'old-key'}}}
            m.set_ssl_certificate(nil, 'http://backend', 1)
            assert(cache['test.example.com:autocert_lock'] == 'new-owner', 'late request must not release a replacement lock')
            assert(cache['test.example.com:c'] == 'ac', 'late request must preserve the new owner marker')
            assert(cache['test.example.com:pair'] == nil, 'late request must discard its old response')
        elseif case == 'lease_expired' then
            on_request = function()
                cache['test.example.com:autocert_lock'] = nil
                cache['test.example.com:c'], cache['test.example.com:k'] = nil, nil
            end
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'old-cert'}, private_key = {pem = 'old-key'}}}
            m.set_ssl_certificate(nil, 'http://backend', 1)
            assert(cache['test.example.com:pair'] == nil, 'expired owner must not publish a late certificate')
            assert(cache['test.example.com:c'] == nil, 'expired owner must not recreate cached state')
        elseif case == 'lease_new_certificate' then
            on_request = function()
                cache['test.example.com:autocert_lock'] = nil
                m.set_cert_sharedcache('test.example.com', {cert = 'new-cert', pkey = 'new-key'})
            end
            payload = {certificate_signed__latest_multi = {fullchain = {pem = 'old-cert'}, private_key = {pem = 'old-key'}}}
            m.set_ssl_certificate(nil, 'http://backend', 1)
            assert(cache['test.example.com:c'] == true and cache['test.example.com:pair']:find('new-cert', 1, true), 'late response must not overwrite a replacement certificate')
        elseif case == 'lease_tokens' then
            local tokens = {}
            on_request = function()
                tokens[#tokens + 1] = cache['test.example.com:autocert_lock']
            end
            payload = {certificate_signed__latest_multi = {}}
            m.set_ssl_certificate(nil, 'http://backend', 1)
            m.set_ssl_certificate(nil, 'http://backend', 1)
            assert(api_calls == 2, 'failed attempt must release its own lock')
            assert(type(tokens[1]) == 'string', 'autocert lock must identify its owner')
            assert(tokens[1] ~= tokens[2], 'attempts must have distinct ownership tokens')
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
            assert(cache['test.example.com:pair'] == nil and cache['test.example.com:c'] == nil,
                'failed cache update must not expose a certificate/key pair')
        elseif case == 'expire' then
            m.set_cert_sharedcache('test.example.com', {cert = 'cert', pkey = 'key'})
            m.set_cert_sharedcache('other.example.com', {cert = 'other', pkey = 'other-key'})
            m.expire_ssl_certs()
            assert(cache['test.example.com:c'] == nil and cache['test.example.com:k'] == nil,
                'expiration must remove both certificate parts')
            assert(cache['other.example.com:c'] == true and cache['other.example.com:pair']:find('other', 1, true), 'expiration must preserve other domains')
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
