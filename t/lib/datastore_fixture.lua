-- Unique real SNI names keep parallel TLS tests out of each other's keyspace.
return function(strategy, host, port)
    local handler = require 'resty.peter_sslers'
    local domain = assert(require('ngx.ssl').server_name())
    local function read(path)
        local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
    end
    local cert = read('t/cert/wildcard.test.example.com.crt')
    local key = read('t/cert/wildcard.test.example.com.key')
    handler.redis_update_defaults(host, port, 9)
    local red = assert(handler.get_redcon())
    local keys = {'d' .. strategy .. ':' .. domain}
    if strategy == 1 then
        keys[2], keys[3], keys[4] = 'c:' .. domain, 'p:' .. domain, 'i:' .. domain
    end
    local ok, err = pcall(function()
        if strategy == 1 then
            assert(red:hmset(keys[1], 'c', domain, 'p', domain, 'i', domain))
            assert(red:set(keys[2], cert)); assert(red:set(keys[3], key)); assert(red:set(keys[4], cert))
        else
            assert(red:hmset(keys[1], 'f', cert, 'p', key))
        end
    end)
    if not ok then red:del(unpack(keys)); red:close(); error(err) end
    handler.redis_keepalive(red)
    ok, err = pcall(handler.set_ssl_certificate, strategy, nil, nil)
    red = assert(handler.get_redcon())
    assert(red:del(unpack(keys)))
    assert(red:exists(unpack(keys)) == 0, 'fixture keys were not removed')
    handler.redis_keepalive(red)
    assert(ok, err)
end
