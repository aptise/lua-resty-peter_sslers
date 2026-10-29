-- The includes
-- "local ngx" is needed for coverage
local ngx = ngx
local cjson_safe = require "cjson.safe"
local lrucache = require "resty.lrucache"
local mlcache = require "resty.mlcache"
local redis = require "resty.redis"
local ssl = require "ngx.ssl"

-- we may not need resty.http,
-- but including it here is better for memory if we need it
-- this is the pintsized library
local http = require "resty.http"

-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
-- alias functions
local cjson_safe_decode = cjson_safe.decode
local cjson_null = cjson_safe.null
local http_new = http.new
local ngx_DEBUG = ngx.DEBUG
local ngx_ERR = ngx.ERR
local ngx_header = ngx.header
local ngx_log = ngx.log
local ngx_NOTICE = ngx.NOTICE
local ngx_null = ngx.null
local ngx_say = ngx.say
local ngx_var = ngx.var
local ssl_clear_certs = ssl.clear_certs
local ssl_server_name = ssl.server_name

-- These cdata pointers stay in mlcache L1; only PEM is serialized into L2.
local ssl_parse_pem_cert = ssl.parse_pem_cert
local ssl_parse_pem_priv_key = ssl.parse_pem_priv_key
local ssl_set_cert = ssl.set_cert
local ssl_set_priv_key = ssl.set_priv_key

-- our caches
local cert_cache = ngx.shared.cert_cache

-- A worker keeps one mlcache instance. Its L1 contains complete parsed pairs,
-- while the shared L2 contains one packed PEM pair per domain.
local cert_lrucache = nil
local certificate_cache
local certificate_pairing_pem_to_cdata
local deserialize_certificate
local cache_namespace = "peter_sslers:certificates:v1:"
-- Worker PID and a per-worker sequence identify each provisioning attempt.
local autocert_sequence = 0

-- cert_cache_duration is for the shared dict;
-- misses fall back onto Redis/PeterSslers
-- cert_cache can be emptied via the api
local cert_cache_duration = 600
-- lru_cache_duration is for the unshared worker dict;
-- misses fallback on cert_cache/Redis/PeterSslers
-- lru must timeout
local lru_cache_duration = 60
local lru_maxitems = 200  -- allow up to 200 items in the cache
local allowed_redis_strategy = {1, 2, }
local redis_server = '127.0.0.1'
local redis_port = '6379'
local redis_db_number = 9
local _VERSION = '0.5.0'
local redis_options = {}
local api_options = {}
local redis_revision, api_revision = 0, 0
local pool_namespace = tostring({})
local api_endpoints = {}
local api_endpoint_count = 0


local function initialize()
    ngx_log(ngx_NOTICE, "peter_sslers.initialize")
    -- we currently use `initialize_worker`, but this may be used in the future
    return true
end


local function initialize_worker(
    _cert_cache_duration, _lru_cache_duration, _lru_maxitems
    )
    ngx_log(ngx_NOTICE, "peter_sslers.initialize_worker")

    -- copy overrides
    cert_cache_duration = _cert_cache_duration or cert_cache_duration
    lru_cache_duration = _lru_cache_duration or lru_cache_duration
    lru_maxitems = _lru_maxitems or lru_maxitems

    ngx_log(ngx_NOTICE,
        "peter_sslers.initialize_worker | cert_cache_duration ",
        cert_cache_duration
    )
    ngx_log(ngx_NOTICE,
        "peter_sslers.initialize_worker | lru_cache_duration ",
        lru_cache_duration
    )
    ngx_log(ngx_NOTICE,
        "peter_sslers.initialize_worker | lru_maxitems ",
        lru_maxitems
    )

    local lru, err = lrucache.new(lru_maxitems)
    if not lru then error("failed to create the cache: " .. (err or "unknown")) end
    -- mlcache normally uses the shared TTL for L1 too. Cap it without changing
    -- L2 expiry, retaining the separately configurable worker TTL.
    cert_lrucache = {
        get = function(_, key) return lru:get(key) end,
        set = function(_, key, value, ttl)
            if lru_cache_duration > 0 then
                ttl = ttl and math.min(ttl, lru_cache_duration) or lru_cache_duration
            end
            return lru:set(key, value, ttl)
        end,
        delete = function(_, key) return lru:delete(key) end,
        flush_all = function() return lru:flush_all() end,
    }
    certificate_cache, err = mlcache.new(cache_namespace, 'cert_cache', {
        lru = cert_lrucache,
        lru_size = lru_maxitems,
        ttl = cert_cache_duration,
        neg_ttl = cert_cache_duration,
        ipc_shm = 'cert_cache_ipc',
        l1_serializer = deserialize_certificate,
    })
    if not certificate_cache then error('failed to create mlcache: ' .. (err or 'unknown')) end
    return true
end


-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
-- START: these are just some helper functions


local function certificate_pairing()
    -- simple container
    local pairing = {}
          pairing["cert"] = nil
          pairing["pkey"] = nil
    return pairing
end


-- API diagnostic fields are untrusted JSON values. Do not pass tables or
-- JSON-null userdata directly to ngx.log, or serialize their nested contents.
local function api_log_value(value)
    if value == cjson_null then return 'null' end
    local kind = type(value)
    if kind == 'string' or kind == 'number' then return value end
    if kind == 'boolean' then return tostring(value) end
    return '<' .. kind .. '>'
end


local function api_response_to_cert(server_name, response, cert_preferences)
    -- response: api response via `httpc:request_uri(data_uri`
    -- returns: `certificate_pem`
    local cert, pkey
    local certificate_pem = certificate_pairing()
    -- A 200 is authoritative only after validating its certificate fields.
    -- Decode/schema errors must not suppress a later successful lookup.
    certificate_pem.transient = not response or response.status ~= 404

    if not response then
        ngx_log(ngx_ERR, 'API response - no response : ', server_name)
    else
        -- scoping
        local body_value, err, status

        status = response.status
        ngx_log(ngx_DEBUG, "API response - status : ", status)
        -- local headers = response.headers
        -- local body = response.body
        if status == 200 then
            body_value, err = cjson_safe_decode(response.body)
            if type(body_value) == "table" and err == nil then
                -- default cert_preferences
                if cert_preferences == nil then
                    cert_preferences = {
                        'certificate_signed__latest_multi',
                        'certificate_signed__latest_single'
                    }
                end
                local explicit_absence = #cert_preferences > 0
                for index, value in ipairs(cert_preferences) do
                    local _bv = body_value[value]
                    if _bv ~= cjson_null then explicit_absence = false end
                    if type(_bv) == 'table' and type(_bv.fullchain) == 'table'
                        and type(_bv.private_key) == 'table'
                        and type(_bv.fullchain.pem) == 'string'
                        and type(_bv.private_key.pem) == 'string' then
                        cert = _bv.fullchain.pem
                        pkey = _bv.private_key.pem
                        break
                    end
                end
                if explicit_absence and body_value.result ~= 'error'
                    and body_value.instructions == nil and body_value.form_errors == nil then
                    certificate_pem.transient = false
                end
                -- these are for nginx logs
                local _result = body_value["result"]
                local _notes = body_value["notes"]
                if _result ~= nil then
                    ngx_log(ngx_DEBUG, "API response['result'] = ", api_log_value(_result))
                end
                if _notes ~= nil then
                    ngx_log(ngx_DEBUG, "API response['notes'] = ", api_log_value(_notes))
                end
                if body_value["instructions"] ~= nil then
                    ngx_log(ngx_DEBUG, "API response['instructions'] IS NOT NULL. ERROR")
                end
                if body_value["form_errors"] ~= nil then
                    ngx_log(ngx_DEBUG, "API response['form_errors'] IS NOT NULL. ERROR")
                end
            else
                ngx_log(ngx_DEBUG, "ERROR:", err, ' or body_value == nil')
            end
        elseif status == 404 then
            ngx_log(ngx_DEBUG, "API response 404 : ", server_name)
            body_value, err = cjson_safe_decode(response.body)
            if type(body_value) == "table" then
                -- we expect a 'message' field
                ngx_log(ngx_DEBUG,
                    "API response error : ", server_name,
                    " : ", api_log_value(body_value['message'])
                )
            end
        else
            ngx_log(ngx_ERR,
                'API response - bad response : ', server_name ,
                " : ", status
            )
        end
    end
    if cert ~= nil and pkey ~= nil then
        certificate_pem.transient = false
        ngx_log(ngx_DEBUG, "API response HIT for : ", server_name)
        certificate_pem['cert'] = cert
        certificate_pem['pkey'] = pkey
    else
        ngx_log(ngx_DEBUG, "API response MISS for : ", server_name)
    end
    return certificate_pem
end


local function certificate_pairing_data(cert)
    -- returns true or false based on the validity of a certificate_pairing
    if cert ~= nil and cert['cert'] ~= nil and cert['pkey'] ~= nil then
        return true
    else
        return false
    end
end


local function has_failmarker(cert)
    -- returns true if failmarker is present
    if cert['cert'] == 'x' or cert['pkey'] == 'x' then
        return true
    end
    return false
end


local function has_autocertmarker(cert)
    -- returns true if autocertmarker is present
    if cert['cert'] == 'ac' or cert['pkey'] == 'ac' then
        return true
    end
    return false
end


local function certificate_pairing_validate(cert)
    if certificate_pairing_data(cert) then
        if has_failmarker(cert) then
            return false
        end
        if has_autocertmarker(cert) then
            return false
        end
        return true
    else
        return false
    end
end


certificate_pairing_pem_to_cdata = function(certificate_pem, certificate_cdata)
    local cert, cert_err = ssl_parse_pem_cert(certificate_pem['cert'])
    local pkey, key_err = ssl_parse_pem_priv_key(certificate_pem['pkey'])
    certificate_cdata['cert'] = cert
    certificate_cdata['pkey'] = pkey
    if not cert or not pkey then
        ngx_log(ngx_ERR, 'invalid certificate PEM: ', cert_err or key_err or 'unknown')
    end
    return certificate_cdata
end


deserialize_certificate = function(packed)
    local separator = packed:find(string.char(0), 1, true)
    if not separator then return nil, 'invalid cached certificate pair' end
    local parsed = certificate_pairing_pem_to_cdata({
        cert = packed:sub(1, separator - 1), pkey = packed:sub(separator + 1),
    }, {})
    if not parsed.cert or not parsed.pkey then return nil, 'invalid cached PEM' end
    return parsed
end


-- function certificate_pairing_pem_to_der(certificate_pem, certificate_der)
--  certificate_der['cert'] = ssl_cert_pem_to_der(certificate_pem['cert'])
--  certificate_der['pkey'] = ssl_priv_key_pem_to_der(certificate_pem['pkey'])
--  return certificate_der
-- end



local function set_autocertmarker_sharedcache(server_name)
    -- The mlcache callback already established a cache miss. This flag is only
    -- status metadata; the owned lease is the provisioning coordination state.
    return cert_cache:set(server_name .. ':c', 'ac', cert_cache_duration)
end


local function clear_autocertmarker_sharedcache(server_name)
    if cert_cache:get(server_name .. ':c') == 'ac' then
        cert_cache:delete(server_name .. ':c')
        cert_cache:delete(server_name .. ':k') -- legacy marker cleanup on reload
    end
end


local function release_autocert_lock(server_name, lock_key, token)
    if cert_cache:get(lock_key) ~= token then return end
    clear_autocertmarker_sharedcache(server_name)
    cert_cache:delete(lock_key)
end


local function set_cert_lrucache(server_name, certificate_cdata)
    ngx_log(ngx_DEBUG, "caching cert & key cdata into the worker : ", server_name)
    cert_lrucache:set(server_name, certificate_cdata, lru_cache_duration)
end


local function set_cert_sharedcache(server_name, certificate_pem)
    ngx_log(ngx_DEBUG, "caching PEM cert & key into the shared cache : ", server_name)
    local ok, err = certificate_cache:set(server_name, nil,
        certificate_pem.cert .. string.char(0) .. certificate_pem.pkey)
    if not ok then
        certificate_cache:delete(server_name)
        cert_cache:delete(server_name .. ':c')
        ngx_log(ngx_ERR, 'failed to cache certificate pair: ', err)
        return nil, err
    end
    -- Status metadata contains no duplicate private keys or certificates.
    local indexed, index_err = cert_cache:set(server_name .. ':c', true, cert_cache_duration)
    if not indexed then ngx_log(ngx_ERR, 'failed to index cached certificate: ', index_err) end
    return true
end


-- Configuration is copied and certificates are parsed once per configuration,
-- never during individual handshakes. Passwords never appear in pool names.
local function connection_options(options, is_redis)
    assert(type(options) == 'table', 'connection options must be a table')
    local result = {}
    local allowed = {username = true, password = true, ssl = is_redis,
        ssl_verify = true, server_name = true, client_cert = true,
        client_key = true, timeout = true, authorization = not is_redis}
    for key, value in pairs(options) do
        assert(allowed[key], 'unknown connection option: ' .. tostring(key))
        result[key] = value
    end
    for _, key in ipairs({'username', 'password', 'server_name', 'authorization'}) do
        assert(result[key] == nil or type(result[key]) == 'string', key .. ' must be a string')
    end
    assert(result.ssl == nil or type(result.ssl) == 'boolean', 'ssl must be a boolean')
    assert(result.ssl_verify == nil or type(result.ssl_verify) == 'boolean', 'ssl_verify must be a boolean')
    if result.ssl_verify == nil then result.ssl_verify = true end
    assert(result.timeout == nil or (type(result.timeout) == 'number' and result.timeout > 0),
        'timeout must be a positive number of milliseconds')
    assert(not result.username or result.password ~= nil, 'username requires password')
    assert(not result.authorization or (not result.username and not result.password),
        'authorization and username/password are mutually exclusive')
    assert(not result.authorization or not result.authorization:find('[\r\n]'), 'invalid authorization header')
    assert((result.client_cert == nil) == (result.client_key == nil),
        'client_cert and client_key must be supplied together')
    if result.client_cert ~= nil then
        assert(not is_redis or result.ssl, 'client certificates require ssl=true')
        assert(type(result.client_cert) == 'string' and type(result.client_key) == 'string',
            'client_cert and client_key must be PEM strings')
        local err
        result.ssl_client_cert, err = ssl_parse_pem_cert(result.client_cert)
        assert(result.ssl_client_cert, 'invalid client certificate: ' .. (err or 'unknown'))
        result.ssl_client_priv_key, err = ssl_parse_pem_priv_key(result.client_key)
        assert(result.ssl_client_priv_key, 'invalid client private key: ' .. (err or 'unknown'))
        result.client_cert, result.client_key = nil, nil
    end
    if not is_redis and result.password then
        result.authorization = 'Basic ' .. ngx.encode_base64((result.username or '') .. ':' .. result.password)
        result.username, result.password = nil, nil
    end
    return result
end


local function redis_update_defaults(_redis_server, _redis_port, _redis_db_number, options)
    -- override system defaults
    local configured = options and connection_options(options, true)
    redis_server = _redis_server
    redis_port = _redis_port
    redis_db_number = _redis_db_number
    if configured then
        redis_options = configured
        redis_revision = redis_revision + 1
    end
end


local function api_update_defaults(options)
    api_options = connection_options(options, false)
    api_revision = api_revision + 1
end


local function get_redcon()
    -- this sets up our redis connection
    -- it checks to see if it is a pooled connection (ie, reused),
    -- and changes to db9 if it is new
    -- Setup Redis connection
    local redcon = redis:new()
    if redis_options.timeout then redcon:set_timeout(redis_options.timeout) end
    if redis_options.ssl then
        local major, minor = tostring(redis._VERSION):match('^(%d+)%.(%d+)')
        if not major or (tonumber(major) == 0 and tonumber(minor) < 28) then
            redcon:close()
            return nil, 'Redis TLS requires lua-resty-redis >= 0.28'
        end
    end
    if redis_options.ssl_client_cert then
        -- lua-resty-redis has no public client-certificate setter. Isolate its
        -- socket access here and fail closed if the required API is unavailable.
        local sock = rawget(redcon, '_sock')
        if not sock or type(sock.setclientcert) ~= 'function' then
            redcon:close()
            return nil, 'Redis client certificate support is unavailable'
        end
        local ok, err = sock:setclientcert(redis_options.ssl_client_cert, redis_options.ssl_client_priv_key)
        if not ok then redcon:close(); return nil, err end
    end
    local connect_options = {
        pool = 'peter_sslers:redis:' .. pool_namespace .. ':' .. redis_revision
            .. ':' .. redis_server .. ':' .. redis_port .. ':' .. redis_db_number,
        ssl = redis_options.ssl,
        ssl_verify = redis_options.ssl_verify ~= false,
        server_name = redis_options.server_name or redis_server,
    }
    -- Connect to redis.  NOTE: this is a pooled connection
    ngx_log(ngx_DEBUG, "Redis: about to connect to redis: ", redis_server, ":", redis_port)
    local called, ok, err = pcall(redcon.connect, redcon, redis_server, redis_port, connect_options)
    if not called then err, ok = ok, nil end
    if not ok then
        ngx_log(ngx_ERR, "Redis: failed to connect to redis: ", err)
        return nil, err
    end
    -- Change the redis DB to the port
    -- We only have to do this on new connections
    local times, err = redcon:get_reused_times()
    if err or type(times) ~= 'number' or times < 0 then
        err = err or 'invalid connection reuse count'
        if redcon.close then redcon:close() end
        ngx_log(ngx_ERR, "Redis: failed to detect times: ", err)
        return nil, err
    end
    if times <= 0 then
        if redis_options.password then
            local ok, err
            if redis_options.username then
                ok, err = redcon:auth(redis_options.username, redis_options.password)
            else
                ok, err = redcon:auth(redis_options.password)
            end
            if not ok then
                redcon:close()
                return nil, 'Redis authentication failed'
            end
        end
        ngx_log(ngx_DEBUG, "Redis: changing to db:", redis_db_number, ", times:", times)
        local ok, err = redcon:select(redis_db_number)
        if not ok then
            if redcon.close then redcon:close() end
            ngx_log(ngx_ERR, "Redis: failed to select database: ", err)
            return nil, err
        end
    end
    return redcon
end


local function redis_keepalive(redcon)
    -- put `redcode` into the connection pool
    -- * pool size = 100
    -- * idle time = 10s
    -- note: this will close the connection
    local ok, err = redcon:set_keepalive(10000, 100)
    if not ok then
        ngx_log(ngx_ERR, "Redis: failed to set keepalive: ", err)
        return
    end
end


-- HMGET returns an array for both hits and misses, false on a Redis error,
-- and nil on a transport error. Only an all-null array is a clean miss.
local function redis_domain_data(redcon, key_domain, ...)
    local data, err = redcon:hmget(key_domain, ...)
    if err or type(data) ~= 'table' then
        err = err or 'invalid HMGET response'
        ngx_log(ngx_ERR, 'Redis: failed to query domain(', key_domain, ') Err: ', err)
        return nil, err
    end
    local count = select('#', ...)
    local all_missing = true
    for index = 1, count do
        if data[index] ~= ngx_null then all_missing = false end
    end
    if all_missing then return nil end
    for index = 1, count do
        if type(data[index]) ~= 'string' then
            err = 'incomplete or invalid Redis domain fields'
            ngx_log(ngx_ERR, 'Redis: ', err, ' for domain(', key_domain, ')')
            return nil, err
        end
    end
    return data
end


local function redis_certificate_part(redcon, key)
    local value, err = redcon:get(key)
    if err or type(value) ~= 'string' then
        err = err or 'missing or invalid Redis certificate part'
        ngx_log(ngx_ERR, 'Redis: failed to retrieve part(', key, ') Err: ', err)
        return nil, err
    end
    return value
end


local function prime_1__query_redis(redcon, _server_name)
    -- Return a pair, a clean miss (nil), or a retryable failure (nil, err).
    ngx_log(ngx_DEBUG, "Redis: prime_1__query_redis : ", _server_name)
    local domain_data, err = redis_domain_data(redcon, 'd1:' .. _server_name, 'c', 'p', 'i')
    if not domain_data then return nil, err end

    local pkey, cert, cacertchain
    pkey, err = redis_certificate_part(redcon, 'p:' .. domain_data[2])
    if not pkey then return nil, err end
    cert, err = redis_certificate_part(redcon, 'c:' .. domain_data[1])
    if not cert then return nil, err end
    cacertchain, err = redis_certificate_part(redcon, 'i:' .. domain_data[3])
    if not cacertchain then return nil, err end

    local certificate_pem = certificate_pairing()
    certificate_pem.cert = cert .. "\n" .. cacertchain
    certificate_pem.pkey = pkey
    return certificate_pem
end


local function prime_2__query_redis(redcon, _server_name)
    -- Return a pair, a clean miss (nil), or a retryable failure (nil, err).
    ngx_log(ngx_DEBUG, "Redis: prime_2__query_redis : ", _server_name)
    local domain_data, err = redis_domain_data(redcon, 'd2:' .. _server_name, 'p', 'f')
    if not domain_data then return nil, err end

    local certificate_pem = certificate_pairing()
    certificate_pem.cert = domain_data[2]
    certificate_pem.pkey = domain_data[1]
    return certificate_pem
end


-- SNI is client input. Accept DNS names (including IDNA ASCII labels),
-- and canonicalize before using a name in a cache key or backend request.
local function canonical_server_name(name)
    if type(name) ~= 'string' then return nil end
    name = name:lower():gsub('%.$', '')
    if #name == 0 or #name > 253 or name:find('[^a-z0-9%.%-]')
        or name:find('..', 1, true) then return nil end
    for label in name:gmatch('[^.]+') do
        if #label > 63 or not label:match('^[a-z0-9]')
            or not label:match('[a-z0-9]$') then return nil end
    end
    if name:sub(1, 1) == '.' or name:sub(-1) == '.' then return nil end
    return name
end


local function api_request(fallback_server, uri, params)
    local options = api_options
    if options.ssl_client_cert and not uri:match('^https://') then
        return nil, 'API client certificates require HTTPS'
    end
    local httpc = http_new()
    if options.timeout then httpc:set_timeout(options.timeout) end
    params.headers = params.headers or {}
    if options.authorization then params.headers.Authorization = options.authorization end
    params.ssl_verify = options.ssl_verify ~= false
    params.ssl_server_name = options.server_name
    params.ssl_client_cert = options.ssl_client_cert
    params.ssl_client_priv_key = options.ssl_client_priv_key
    if options.ssl_client_cert then
        local major, minor, patch = tostring(http._VERSION):match('^(%d+)%.(%d+)%.(%d+)')
        local supported = major and (tonumber(major) > 0 or tonumber(minor) > 17
            or (tonumber(minor) == 17 and tonumber(patch) >= 1))
        if not supported or not httpc.sock or type(httpc.sock.setclientcert) ~= 'function' then
            return nil, 'HTTP client certificate support is unavailable'
        end
    end
    if api_revision > 0 then
        if not api_endpoints[fallback_server] then
            api_endpoint_count = api_endpoint_count + 1
            api_endpoints[fallback_server] = api_endpoint_count
        end
        params.pool = 'peter_sslers:api:' .. pool_namespace .. ':' .. api_revision
            .. ':' .. api_endpoints[fallback_server]
    end
    return httpc:request_uri(uri, params)
end


local function query_api_upstream(
    fallback_server, server_name, cert_preferences
)
    -- fallback_server : http(s) server root for peter_sslers installation
    -- server_name : active `ssl.server_name`
    -- cert_preferences : array of api keys to prefer
    --
    -- returns: certificate_pem - a pairing that may be valid or invalid
    ngx_log(ngx_DEBUG, "query_api_upstream : ", server_name)

    server_name = canonical_server_name(server_name)
    if not server_name then return certificate_pairing() end

    local data_uri = fallback_server .. "/domain/" .. server_name ..
        "/config.json?openresty=1"
    ngx_log(ngx_DEBUG, "querying upstream API server at: ", data_uri)
    local response, err = api_request(fallback_server, data_uri, {method = "GET", })
    -- response could be nil on a failure, but passing it into the
    -- following function will give us an empty cert
    local certificate_pem = api_response_to_cert(
        server_name, response, cert_preferences
    )
    return certificate_pem
end


local function query_api_autocert(
    fallback_server, server_name, cert_preferences
)
    -- fallback_server : http(s) server root for peter_sslers installation
    -- server_name : active `ssl.server_name`
    -- cert_preferences : array of api keys to prefer
    --
    -- returns: certificate_pem - a pairing that may be valid or invalid
    ngx_log(ngx_DEBUG, "query_api_autocert : ", server_name)

    server_name = canonical_server_name(server_name)
    if not server_name then return certificate_pairing() end

    local data_uri = fallback_server .. "/api/domain/autocert.json?openresty=1"
    ngx_log(ngx_DEBUG, "querying autocert API server at: ", data_uri)
    local response, err = api_request(fallback_server, data_uri, {
        method = "POST",
        body = "domain_name=" .. server_name,
        headers = {["Content-Type"] = "application/x-www-form-urlencoded"},
    })
    -- response could be nil on a failure, but passing it into the
    -- following function will give us an empty cert
    local certificate_pem = api_response_to_cert(
        server_name, response, cert_preferences
    )
    return certificate_pem
end


-- END helper functions
-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~

-- =============================================================================

-- START MAIN LOGIC


local function fetch_certificate(
    context, server_name, redis_strategy, fallback_server, enable_autocert, cert_preferences
)
    local certificate_pem = certificate_pairing()
    local transient, parsed = false, nil
    -- our upstream providers will return
    -- a `certificate_pairing()` or `nil` value
    -- certificate_pem will be our main focus

    if redis_strategy ~= nil then
        -- ok, try to get it from redis
        ngx_log(ngx_DEBUG, "Redis: lookup enabled")
        if not allowed_redis_strategy[redis_strategy] then
            ngx_log(ngx_ERR,
                "Redis: invalid `redis_strategy` not (1, 2) is `",
                redis_strategy, "`"
            )
            context.skip = true
            return nil, nil, -1
        end

        -- grab redis connection
        local redcon, err = get_redcon()
        if redcon == nil then
            ngx_log(ngx_ERR, "Redis: could not get connection")
            transient = true
        else
            -- actually query redis
            if redis_strategy == 1 then
                certificate_pem, err = prime_1__query_redis(redcon, server_name)
            elseif redis_strategy == 2 then
                certificate_pem, err = prime_2__query_redis(redcon, server_name)
            end
            if err then
                transient = true
                -- A failed command may leave an unusable socket; do not
                -- return it to the keepalive pool.
                redcon:close()
            else
                redis_keepalive(redcon)
            end
        end
    end

    if certificate_pairing_validate(certificate_pem) and not parsed then
        parsed = certificate_pairing_pem_to_cdata(certificate_pem, {})
        if not certificate_pairing_data(parsed) then
            certificate_pem = certificate_pairing()
            parsed = nil
            transient = true
        end
    end

    -- use a fallback search?
    -- checking for nil first is cheaper than checking
    -- `certificate_pairing_data`
    if fallback_server ~= nil then
        if not certificate_pairing_data(certificate_pem) then
            if enable_autocert ~= nil then
                -- fallback autocert
                ngx_log(ngx_DEBUG, "UpstreamAPI: autocert enabled")
                -- wrap this within an autocert marker;
                -- this will keep other workers from hitting it
                -- Atomic acquisition closes the race between cache miss
                -- and marker creation. A bounded lease recovers crashed workers.
                local lock_key = server_name .. ":autocert_lock"
                autocert_sequence = autocert_sequence + 1
                local token = ngx.worker.pid() .. ':' .. autocert_sequence
                local acquired = cert_cache:add(lock_key, token, cert_cache_duration)
                if not acquired then context.skip = true; return nil, nil, -1 end
                context.lock_key, context.lock_token = lock_key, token
                set_autocertmarker_sharedcache(server_name)
                local ok, result = pcall(query_api_autocert,
                    fallback_server, server_name, cert_preferences)
                -- The API call yields. Its lease may have expired or
                -- been flushed and acquired by another worker meanwhile.
                if cert_cache:get(lock_key) ~= token then
                    ngx_log(ngx_DEBUG, "discarding obsolete autocert response: ", server_name)
                    context.skip = true
                    return nil, nil, -1
                end
                if not ok then
                    ngx_log(ngx_ERR, "autocert request failed: ", result)
                    context.transient = true
                    return nil, 'autocert request failed'
                end
                certificate_pem = result
            else
                -- fallback query
                ngx_log(ngx_DEBUG, "UpstreamAPI: lookup enabled")
                certificate_pem = query_api_upstream(
                    fallback_server, server_name, cert_preferences
                )
            end
        end
    end

    transient = transient or (certificate_pem and certificate_pem.transient)
    if certificate_pairing_validate(certificate_pem) and not parsed then
        parsed = certificate_pairing_pem_to_cdata(certificate_pem, {})
        if not certificate_pairing_data(parsed) then
            certificate_pem = certificate_pairing()
            parsed = nil
            transient = true
        end
    end
    -- Recheck after PEM parsing, and retain ownership until publishing
    -- the cache result. A stale attempt must not publish negative state.
    if context.lock_key and cert_cache:get(context.lock_key) ~= context.lock_token then
        context.skip = true
        return nil, nil, -1
    end
    if certificate_pairing_validate(certificate_pem) then
        context.packed = certificate_pem.cert .. string.char(0) .. certificate_pem.pkey
        context.cdata = parsed
        ngx_log(ngx_DEBUG, 'caching PEM cert & key into the shared cache : ', server_name)
        return context.packed
    end
    ngx_log(ngx_DEBUG, 'failed to retrieve PEM for : ', server_name)
    if transient then
        context.transient = true
        return nil, 'upstream certificate lookup failed'
    end
    context.absent = true
    return nil
end


local function set_ssl_certificate(
    redis_strategy, fallback_server, enable_autocert, cert_preferences
)
    -- main functionality
    --   queries datastores for certificate data, loads into nginx/openresy
    -- redis_strategy : nil = Do not use Redis;
    --                  1,2 = peter_sslers redis-prime versions
    -- fallback_server : http(s) server root for peter_sslers installation
    -- enable_autocert? : nil = NO; not-nil = YES
    -- cert_preferences : an array to attempt searching in payload
    --                    should be {"certificate_signed__latest_single",
    --                               "certificate_signed__latest_multi"}
    --
    -- Parsed objects remain worker-local with the configured L1 TTL cap.
    -- mlcache IPC applies updates/expiration before the next certificate lookup.

    local server_name = ssl_server_name()
    ngx_log(ngx_DEBUG, "set_ssl_certificate : ", server_name)

    -- Check for SNI request.
    if server_name == nil then
        ngx_log(ngx_DEBUG, "SNI Not present - performing IP lookup")

        -- don't bother with IP lookups
        -- exit out and just fall back on the default ssl cert
        return
    end
    server_name = canonical_server_name(server_name)
    if not server_name then return end
    ngx_log(ngx_DEBUG, "SNI Lookup for : ", server_name)

    -- update() needs a positive timeout: zero skips IPC event reads entirely.
    local updated, update_err = certificate_cache:update(0.01)
    if not updated then
        ngx_log(ngx_ERR, 'failed to synchronize certificate cache: ', update_err)
        return
    end
    local certificate_cdata, cache_err, hit_level = certificate_cache:get(server_name)
    if hit_level == -1 then
        ngx_log(ngx_DEBUG, 'cert_lrucache MISS for : ', server_name)
        ngx_log(ngx_DEBUG, 'shared `cert_cache` MISS for : ', server_name)
        if cert_cache:get(server_name .. ':autocert_lock') then return end
        local context = {}
        certificate_cdata, cache_err, hit_level = certificate_cache:get(server_name, {
            resty_lock_opts = enable_autocert ~= nil and {
                exptime = cert_cache_duration > 0 and cert_cache_duration or 60,
                timeout = 0,
            } or nil,
            l1_serializer = function(packed)
                if packed == context.packed then return context.cdata end
                return deserialize_certificate(packed)
            end,
        }, fetch_certificate, context, server_name, redis_strategy, fallback_server, enable_autocert, cert_preferences)
        if not cache_err and not context.skip then
            if certificate_cdata then
                cert_cache:set(server_name .. ':c', true, cert_cache_duration)
                ngx_log(ngx_DEBUG, 'caching cert & key cdata into the worker : ', server_name)
            elseif context.absent then
                cert_cache:set(server_name .. ':c', 'x', cert_cache_duration)
            end
        elseif cache_err and context.cdata then
            -- A valid backend result may still serve this handshake when shared
            -- memory is full. Do not create an untracked/stale L1 cache entry.
            certificate_cdata = context.cdata
        end
        if context.lock_key then
            release_autocert_lock(server_name, context.lock_key, context.lock_token)
        end
        if cache_err and context.transient then
            ngx_log(ngx_DEBUG, 'unable to provide ssl for : ', server_name, ' ', cache_err)
            return
        end
    elseif hit_level == 1 then
        ngx_log(ngx_DEBUG, 'cert_lrucache HIT for : ', server_name)
    elseif hit_level == 2 then
        ngx_log(ngx_DEBUG, 'cert_lrucache MISS for : ', server_name)
        ngx_log(ngx_DEBUG, 'shared `cert_cache` HIT for : ', server_name)
        if certificate_cdata then ngx_log(ngx_DEBUG, 'caching cert & key cdata into the worker : ', server_name) end
    end
    if cache_err then ngx_log(ngx_ERR, 'certificate cache lookup failed: ', cache_err) end
    if certificate_pairing_data(certificate_cdata) then
        -- since we have a certs for this server, now we can continue...
        ngx_log(ngx_DEBUG, "can provide ssl for : ", server_name)
        ssl_clear_certs()

        -- scoping
        local ok, err

        -- Set cert
        ok, err = ssl_set_cert(certificate_cdata['cert'])
        if not ok then
            ngx_log(ngx_ERR,
                "failed to set ssl certificate : ", server_name,
                " ", err
            )
            return
        else
            ngx_log(ngx_DEBUG,
                "set ssl certificate : ", server_name
            )
        end

        -- Set key
        ok, err = ssl_set_priv_key(certificate_cdata['pkey'])
        if not ok then
            ngx_log(ngx_ERR,
                "failed to set ssl private key : ", server_name,
                " ", err
            )
            return
        else
            ngx_log(ngx_DEBUG, "set ssl private key : ", server_name)
        end
    else
        ngx_log(ngx_DEBUG, "unable to provide ssl for : ", server_name)
    end
end


local function status_ssl_certs()
    ngx_log(ngx_NOTICE, "status_ssl_certs")
    ngx_header.content_type = 'application/json'
    ngx_header["x-peter-sslers"] = _VERSION
    -- handmade json value
    local ks_valid = {}
    local ks_invalid = {}
    local ks_autocert = {}
    -- max count is 1024, but specify it anyways
    local all_keys = cert_cache:get_keys(1024)

    -- `all_keys` is a table of (idx, key)
    for idx, k in pairs(all_keys) do
        local _domain = k:sub(0,-3)
        local _ext = k:sub(-2,-1)
        -- each domain has a duplicate on "{DOMAIN}:k" and "{DOMAIN}:v"
        -- we only need one
        if _ext == ':c' then
            local v = cert_cache:get(k)
            -- ngx_log(ngx_DEBUG, "idx ", idx)
            -- ngx_log(ngx_DEBUG, "k ", k)
            -- ngx_log(ngx_DEBUG, "_domain ", _domain)
            -- ngx_log(ngx_DEBUG, "_ext ", _ext)
            -- ngx_log(ngx_DEBUG, "v ", v)
            local remaining = certificate_cache:peek(_domain)
            if v == 'x' and remaining ~= nil then
                table.insert(ks_invalid, _domain)
            elseif v == 'ac' then
                table.insert(ks_autocert, _domain)
            elseif v == true and remaining ~= nil then
                table.insert(ks_valid, _domain)
            end
        end
    end

    local _ks_valid = ''
    for idx, k in pairs(ks_valid) do
        _ks_valid = _ks_valid .. '"' .. k .. '",'
    end
    -- remove the last ,
    _ks_valid = _ks_valid:sub(1, -2)

    local _ks_invalid = ''
    -- `_ks_invalid` is a table of (idx, key)
    for idx, k in pairs(ks_invalid) do
        _ks_invalid = _ks_invalid .. '"' .. k .. '",'
    end
    -- remove the last ,
    _ks_invalid = _ks_invalid:sub(1, -2)

    local _ks_autocert = ''
    -- `_ks_autocert` is a table of (idx, key)
    for idx, k in pairs(ks_autocert) do
        _ks_autocert = _ks_autocert .. '"' .. k .. '",'
    end
    -- remove the last ,
    _ks_autocert = _ks_autocert:sub(1, -2)

    local ks = '{"valid": [' .. _ks_valid .. '], "invalid": [' .. _ks_invalid ..
               '], "autocert": [' .. _ks_autocert .. ']}'
    local expiries = '{"ngx.shared.cert_cache": ' .. cert_cache_duration ..
                     ', "resty.lrucache": ' .. lru_cache_duration .. '}'
    local maxitems = '{"resty.lrucache": ' .. lru_maxitems .. '}'
    local rval = '{"result": "success", "note": "This is a max(1024) ' ..
                 'listening of keys in the ngx.shared.DICT `cert_cache`. ' ..
                 'This does not show the worker\'s own LRU cache, or Redis."' ..
                 ', "keys": ' .. ks .. ', "config": {"expiries": ' ..
                 expiries .. ', "maxitems": ' .. maxitems .. '}, "server": ' ..
                 '"peter_sslers:openresty", "server_version": "' ..
                 _VERSION .. '"}'
    ngx_say(rval)
    return
end


local function expire_ssl_certs()
    ngx_log(ngx_NOTICE, "expire_ssl_certs")
    ngx_header.content_type = 'application/json'
    ngx_header["x-peter-sslers"] = _VERSION
    local prefix = ngx_var.location
    if ngx_var.request_uri == prefix .. '/all' then
        local ok, err = certificate_cache:purge()
        if not ok then
            ngx_log(ngx_ERR, 'failed to purge certificate cache: ', err)
            ngx.status = 503
            ngx_say('{"result":"error","reason":"Cache invalidation failed"}')
            return
        end
        ngx_say(
            '{"result": "success", "expired": "all", ' ..
            '"server": "peter_sslers:openresty", ' ..
            '"server_version": "' .. _VERSION .. '"}'
        )
        return
    end
    local _domain = string.match(
        ngx_var.request_uri, '^' .. prefix .. '/domain/([%w-.]+)$'
    )
    if _domain then
        local ok, err = certificate_cache:delete(_domain)
        if not ok then
            ngx_log(ngx_ERR, 'failed to expire certificate: ', err)
            ngx.status = 503
            ngx_say('{"result":"error","reason":"Cache invalidation failed"}')
            return
        end
        cert_cache:delete(_domain .. ":pair")
        cert_cache:delete(_domain .. ":c")
        cert_cache:delete(_domain .. ":k")
        ngx_say('{"result": "success", "expired": "domain", "domain": "' ..
                _domain ..'", "server": "peter_sslers:openresty", ' ..
                '"server_version": "' .. _VERSION .. '"}'
                )
        return
    end
    ngx_log(ngx_ERR, "expire_ssl_certs - malformed request")
    ngx.status = 404
    ngx_say('{"result": "error", "expired": "None", "reason": "Unknown URI"' ..
            ', "server": "peter_sslers:openresty", ' ..
            '"server_version": "' .. _VERSION .. '"}'
            )
    return
end

-- needed for tests:
-- * certificate_pairing
-- * certificate_pairing_pem_to_cdata
-- * set_cert_lrucache
-- * set_cert_sharedcache

local _M = {get_redcon = get_redcon,
            api_update_defaults = api_update_defaults,
            valkey_update_defaults = redis_update_defaults,
            redis_keepalive = redis_keepalive,
            redis_update_defaults = redis_update_defaults,
            prime_1__query_redis = prime_1__query_redis,
            prime_2__query_redis = prime_2__query_redis,
            query_api_upstream = query_api_upstream,
            query_api_autocert = query_api_autocert,
            set_ssl_certificate = set_ssl_certificate,
            expire_ssl_certs = expire_ssl_certs,
            status_ssl_certs = status_ssl_certs,

            certificate_pairing = certificate_pairing,
            certificate_pairing_pem_to_cdata = certificate_pairing_pem_to_cdata,
            set_cert_lrucache = set_cert_lrucache,
            set_cert_sharedcache = set_cert_sharedcache,

            initialize_worker = initialize_worker,
            initialize = initialize,
            _VERSION = _VERSION,
            }

return _M
