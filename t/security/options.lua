return function(case)
    local handler = assert(loadfile('lib/resty/peter_sslers.lua'))()
    local function read(path)
        local file = assert(io.open(path, 'r'))
        local data = file:read('*a')
        file:close()
        return data
    end
    local cert, key = read('t/cert/test.example.com.crt'), read('t/cert/test.example.com.key')
    local invalid = {
        unknown = {typo = true},
        negative_backoff = {retry_backoff = -1},
        excessive_backoff = {retry_backoff = 61},
        infinite_backoff = {retry_backoff = math.huge},
        username_only = {username = 'audit'},
        cert_only = {ssl = true, client_cert = cert},
        cert_plaintext = {client_cert = cert, client_key = key},
        invalid_cert = {ssl = true, client_cert = 'bad', client_key = key},
        invalid_key = {ssl = true, client_cert = cert, client_key = 'bad'},
        invalid_timeout = {timeout = -1},
        invalid_verify = {ssl_verify = 'yes'},
        false_cert = {client_cert = false, client_key = false},
    }
    if invalid[case] then
        assert(not pcall(handler.redis_update_defaults, '127.0.0.1', 6379, 9, invalid[case]),
            'invalid store options were accepted')
        return
    end
    if case == 'header_injection' then
        local ok, err = pcall(handler.api_update_defaults, {authorization = 'secret\r\nInjected: yes'})
        assert(not ok and not tostring(err):find('secret', 1, true), 'header injection was accepted or leaked')
        return
    elseif case == 'conflicting_auth' then
        assert(not pcall(handler.api_update_defaults,
            {authorization = 'Bearer token', username = 'audit', password = 'secret'}))
        return
    end
    if case == 'unsupported_http_mtls' then
        local saved_http = package.loaded['resty.http']
        local called = false
        package.loaded['resty.http'] = {_VERSION = '0.15.0', new = function() return {
            sock = {setclientcert = function() return true end},
            request_uri = function() called = true; error('unsupported client must not send a request') end,
        } end}
        local ok, err = pcall(function()
            local configured = assert(loadfile('lib/resty/peter_sslers.lua'))()
            configured.api_update_defaults({client_cert = cert, client_key = key})
            local pair = configured.query_api_upstream('https://backend.test', 'test.example.com')
            assert(not called and not pair.cert and pair.transient, 'unsupported HTTP mTLS did not fail closed')
        end)
        package.loaded['resty.http'] = saved_http
        assert(ok, err)
        return
    end
    local saved = package.loaded['resty.redis']
    local connected, authenticated, selected, closed = false, false, false, false
    local captured_options
    local connection = {
        connect = function(_, _, _, options) connected = true; captured_options = options; return true end,
        get_reused_times = function() return 0 end,
        auth = function(_, password) authenticated = password == 'secret'; return false, 'secret echoed by peer' end,
        select = function() selected = true; return true end,
        close = function() closed = true; return true end,
    }
    package.loaded['resty.redis'] = {_VERSION = '0.32', new = function() return connection end}
    local ok, err = pcall(function()
        handler = assert(loadfile('lib/resty/peter_sslers.lua'))()
        if case == 'unsupported_tls' then
            package.loaded['resty.redis']._VERSION = '0.27'
            handler.valkey_update_defaults('127.0.0.1', 6379, 9, {ssl = true})
            local con, reason = handler.get_redcon()
            assert(not con and reason:find('requires', 1, true) and closed and not connected,
                'unsupported Redis TLS did not fail closed')
        elseif case == 'unsupported_mtls' then
            handler.valkey_update_defaults('127.0.0.1', 6379, 9,
                {ssl = true, client_cert = cert, client_key = key})
            local con, reason = handler.get_redcon()
            assert(not con and reason:find('unavailable', 1, true) and closed and not connected,
                'unsupported mTLS did not fail closed')
        else
            assert(case == 'auth_failure', 'unknown security option test')
            local options = {password = 'secret', ssl = true}
            handler.redis_update_defaults('backend.test', 6379, 9, options)
            options.password = 'mutated'
            local con, reason = handler.get_redcon()
            assert(not con and authenticated and not selected and closed, 'AUTH failure did not stop database selection')
            assert(not reason:find('secret', 1, true), 'authentication error leaked a password')
            assert(not captured_options.pool:find('secret', 1, true), 'pool name leaked a password')
            assert(captured_options.ssl_verify == true and captured_options.server_name == 'backend.test',
                'TLS verification and hostname must default safely')
        end
    end)
    package.loaded['resty.redis'] = saved
    assert(ok, err)
end
