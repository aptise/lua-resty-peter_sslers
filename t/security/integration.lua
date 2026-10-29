return function(case, directory)
    local json = require 'cjson.safe'
    local function read(path)
        local file = assert(io.open(path, 'r'))
        local data = file:read('*a')
        file:close()
        return data
    end
    local ports = assert(json.decode(read(directory .. '/ports.json')))
    local handler = require 'resty.peter_sslers'
    local cert, key = read(directory .. '/client.crt'), read(directory .. '/client.key')
    local function redis_config(port, options, db)
        handler.valkey_update_defaults('127.0.0.1', port, db or 9, options)
    end
    if case == 'store_pool_db' then
        local port = ports.auth
        redis_config(port, {password = 'test-password'}, 9)
        local connection = assert(handler.get_redcon())
        local test_key = 'db-isolation-' .. ports.fixture_id .. '-' .. ngx.worker.pid()
        assert(connection:set(test_key, 'database-nine'))
        handler.redis_keepalive(connection)
        handler.valkey_update_defaults('127.0.0.1', port, 8)
        connection = assert(handler.get_redcon())
        assert(connection:get(test_key) == ngx.null, 'database change reused the wrong selected database')
        assert(connection:set(test_key, 'database-eight'))
        handler.redis_keepalive(connection)
        handler.valkey_update_defaults('127.0.0.1', port, 9)
        connection = assert(handler.get_redcon())
        assert(connection:get(test_key) == 'database-nine', 'database-nine pool was contaminated')
        connection:del(test_key)
        handler.redis_keepalive(connection)
        handler.valkey_update_defaults('127.0.0.1', port, 8)
        connection = assert(handler.get_redcon())
        connection:del(test_key)
        handler.redis_keepalive(connection)
        return
    end
    if case:match('^store_') then
        local options = {timeout = 2000}
        local port = ports.auth
        if case ~= 'store_missing_password' then options.password = 'test-password' end
        if case == 'store_acl' then options.username = 'audit' end
        if case:find('tls', 1, true) then
            options.ssl, options.server_name = true, 'backend.test'
            port = case:find('mtls', 1, true) and ports.mtls or ports.tls
            if port == ports.mtls then options.password = nil end
        end
        if case == 'store_mtls' then options.client_cert, options.client_key = cert, key end
        if case == 'store_bad_hostname_tls' then options.server_name = 'wrong.test' end
        if case == 'store_wrong_password' then options.password = 'incorrect' end
        redis_config(port, options)
        local connection = handler.get_redcon()
        local rejected = case == 'store_missing_password' or case == 'store_wrong_password'
            or case == 'store_bad_hostname_tls' or case == 'store_missing_cert_mtls'
        if rejected then
            assert(not connection, 'invalid credentials or TLS identity must be rejected')
            return
        end
        assert(connection, 'secure store connection failed')
        assert(connection:ping() == 'PONG')
        handler.redis_keepalive(connection)
        local reused = assert(handler.get_redcon())
        assert(reused:get_reused_times() > 0, 'secure connection was not reused')
        assert(reused:ping() == 'PONG')
        handler.redis_keepalive(reused)
        if case == 'store_pool_credentials' then
            redis_config(port, {password = 'incorrect'})
            assert(not handler.get_redcon(), 'new credentials reused an authenticated pool')
        end
        return
    end
    if case == 'prime_formats' then
        redis_config(ports.plain, {})
        local connection = assert(handler.get_redcon())
        local domain = 'secure-test-' .. ports.fixture_id .. '-' .. ngx.worker.pid() .. '.example.com'
        local pem_cert = read('t/cert/test.example.com.crt')
        local pem_key = read('t/cert/test.example.com.key')
        local keys = {'d1:' .. domain, 'd2:' .. domain, 'c:' .. domain, 'p:' .. domain, 'i:' .. domain}
        local ok, err = pcall(function()
            assert(connection:hmset(keys[1], 'c', domain, 'p', domain, 'i', domain))
            assert(connection:hmset(keys[2], 'f', pem_cert, 'p', pem_key))
            assert(connection:set(keys[3], pem_cert))
            assert(connection:set(keys[4], pem_key))
            assert(connection:set(keys[5], pem_cert))
            local first = assert(handler.prime_1__query_redis(connection, domain))
            local second = assert(handler.prime_2__query_redis(connection, domain))
            assert(first.pkey == pem_key and first.cert == pem_cert .. '\n' .. pem_cert)
            assert(second.pkey == pem_key and second.cert == pem_cert)
        end)
        connection:del(unpack(keys))
        handler.redis_keepalive(connection)
        assert(ok, err)
        return
    end
    local options = {username = 'audit', password = 'test-password', timeout = 2000, server_name = 'backend.test'}
    local endpoint = case == 'api_http' and 'http' or 'https'
    local scheme = endpoint
    if case:find('mtls', 1, true) then endpoint = 'https_mtls' end
    if case == 'api_untrusted' then endpoint = 'untrusted' end
    if case == 'api_mtls' or case == 'api_pool_identity_mtls' then
        options.client_cert, options.client_key = cert, key
    end
    if case == 'api_wrong_password' then options.password = 'incorrect' end
    if case == 'api_wrong_hostname' then options.server_name = 'wrong.test' end
    local prefix = '/basic'
    if case == 'api_bearer' then
        options.username, options.password = nil, nil
        options.authorization = 'Bearer test-token'
        prefix = '/bearer'
    end
    handler.api_update_defaults(options)
    local root = scheme .. '://127.0.0.1:' .. ports[endpoint] .. prefix
    local query = case == 'api_autocert' and handler.query_api_autocert or handler.query_api_upstream
    local pair = query(root, 'test.example.com')
    local rejected = case == 'api_untrusted' or case == 'api_wrong_password'
        or case == 'api_wrong_hostname' or case == 'api_missing_cert_mtls'
    if rejected then
        assert(not pair.cert and pair.transient, 'invalid API credentials or TLS identity must fail')
    else
        assert(pair.cert == read('t/cert/test.example.com.crt'), 'secure API certificate lookup failed')
        if case == 'api_pool_identity_mtls' then
            handler.api_update_defaults({username = 'audit', password = 'test-password', server_name = 'backend.test'})
            local next_pair = handler.query_api_upstream(root, 'test.example.com')
            assert(not next_pair.cert and next_pair.transient, 'new client identity reused the previous TLS session')
        end
    end
end
