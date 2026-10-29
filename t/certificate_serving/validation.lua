return function(case, socket_path)
    local handler = require 'resty.peter_sslers'
    if case == 'shared_mismatch' then
        local function read(path)
            local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
        end
        -- Simulate an old worker publishing a pair without key-match validation.
        local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache',
            {ipc_shm = 'cert_cache_ipc'}))
        assert(inspector:set('example.com', nil,
            read('t/cert/test.example.com.crt') .. '\0' .. read('t/cert/example.com.key')))
    end
    local sock = ngx.socket.tcp()
    sock:settimeout(2000)
    assert(sock:connect('unix:' .. socket_path))
    local name = (case == 'mismatch' or case == 'shared_mismatch') and 'example.com' or 'test.example.com'
    local session, err = sock:sslhandshake(nil, name, true)
    sock:close()
    if case:find('_failure', 1, true) then
        assert(not session, 'installation failure allowed a TLS handshake')
        local expected = case == 'clear_failure' and 1 or (case == 'cert_failure' and 2 or 3)
        assert(ngx.shared.installation_control:get('steps') == expected, 'installation continued after failure')
    else
        assert(session, err)
        if case == 'mismatch' or case == 'shared_mismatch' then
            assert(not ngx.shared.installation_control:get('steps'), 'mismatched key cleared default credentials')
        else
            assert(ngx.shared.installation_control:get('steps') == 3)
        end
    end
end
