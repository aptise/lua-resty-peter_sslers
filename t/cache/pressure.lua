return function(scenario, socket_path)
    local handler = require 'resty.peter_sslers'
    local function read(path)
        local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
    end
    local cert = read('t/cert/test.example.com.crt')
    local key = read('t/cert/test.example.com.key')
    local inspector = assert(require('resty.mlcache').new('peter_sslers:certificates:v1:', 'cert_cache'))
    if scenario == 'churn' then
        assert(handler.set_cert_sharedcache('test.example.com', {cert = cert, pkey = key}))
        -- Do not peek at the target while filling: get_stale/peek touches its
        -- shared LRU position and would keep the entry artificially hot.
        for index = 1, 64 do
            assert(handler.set_cert_sharedcache('pressure-' .. index .. '.example.com', {cert = cert, pkey = key}))
        end
        assert(inspector:peek('test.example.com') == nil, 'small dictionary never evicted the target PEM pair')
    end
    for _ = 1, 2 do
        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        assert(sock:connect('unix:' .. socket_path))
        local session, err = sock:sslhandshake(nil, 'test.example.com', true)
        sock:close()
        assert(session, err)
    end
    if scenario == 'oversized' then
        assert(not inspector:peek('test.example.com'), 'oversized PEM unexpectedly fit in shared memory')
        assert(ngx.shared.pressure_control:get('api_calls') == 1, 'usable worker cache was lost under shared-memory pressure')
    else
        assert(not ngx.shared.pressure_control:get('api_calls'), 'L2 eviction discarded a valid worker-local certificate')
    end
end
