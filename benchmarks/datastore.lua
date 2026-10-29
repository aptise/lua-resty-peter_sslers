local host, port, iterations = arg[1], tonumber(arg[2]), tonumber(arg[3])
assert(host and port and iterations and iterations > 0)
local ffi = require 'ffi'
assert(jit.os == 'Linux' or jit.os == 'OSX', 'benchmark clock supports Linux and macOS')
ffi.cdef[[struct sslers_benchmark_timespec { long tv_sec; long tv_nsec; };
    int clock_gettime(int, struct sslers_benchmark_timespec *);]]
local clock = ffi.new('struct sslers_benchmark_timespec[1]')
local monotonic = jit.os == 'OSX' and 6 or 1
local function now()
    assert(ffi.C.clock_gettime(monotonic, clock) == 0)
    return tonumber(clock[0].tv_sec) * 1000000 + tonumber(clock[0].tv_nsec) / 1000
end
local handler = require 'resty.peter_sslers'
handler.valkey_update_defaults(host, port, 9, {timeout = 2000})
local function read(path)
    local file = assert(io.open(path)); local value = file:read('*a'); file:close(); return value
end
local cert, key = read('t/cert/test.example.com.crt'), read('t/cert/test.example.com.key')
local domain = 'benchmark-' .. assert(arg[4], 'fixture namespace required') .. '-' .. ngx.worker.pid() .. '.example.com'
local keys = {'d1:' .. domain, 'd2:' .. domain, 'c:' .. domain, 'p:' .. domain, 'i:' .. domain}
local connection = assert(handler.get_redcon())
assert(connection:hmset(keys[1], 'c', domain, 'p', domain, 'i', domain))
assert(connection:hmset(keys[2], 'f', cert .. '\n' .. cert, 'p', key))
assert(connection:set(keys[3], cert)); assert(connection:set(keys[4], key)); assert(connection:set(keys[5], cert))
local info = assert(connection:info('server'))
handler.redis_keepalive(connection)
-- Keep the sequential baseline and proposed batching independent of production
-- code, so future implementations can still be compared against the same work.
local function serial(red)
    local ids = assert(red:hmget(keys[1], 'c', 'p', 'i'))
    local pkey = assert(red:get('p:' .. ids[2]))
    local leaf = assert(red:get('c:' .. ids[1]))
    local chain = assert(red:get('i:' .. ids[3]))
    return {cert = leaf .. '\n' .. chain, pkey = pkey}
end
local function pipeline(red)
    local ids = assert(red:hmget(keys[1], 'c', 'p', 'i'))
    red:init_pipeline(3)
    red:get('p:' .. ids[2]); red:get('c:' .. ids[1]); red:get('i:' .. ids[3])
    local parts = assert(red:commit_pipeline())
    for i = 1, 3 do assert(type(parts[i]) == 'string') end
    return {cert = parts[2] .. '\n' .. parts[3], pkey = parts[1]}
end
local functions = {serial_reference = serial, pipeline_reference = pipeline,
    current_prime1 = function(red) return handler.prime_1__query_redis(red, domain) end,
    current_prime2 = function(red) return handler.prime_2__query_redis(red, domain) end}
local results = {}
local ok, err = pcall(function()
    -- Warm the JIT and socket pool before collecting measurements.
    for _, query in pairs(functions) do
        for _ = 1, 20 do
            local red = assert(handler.get_redcon()); assert(query(red)); handler.redis_keepalive(red)
        end
    end
    for _, name in ipairs({'serial_reference', 'pipeline_reference', 'current_prime1', 'current_prime2'}) do
        for _, mode in ipairs({'pooled', 'fresh'}) do
            local samples, reused = {}, 0
            if mode == 'fresh' then
                -- Drain the single-client pool before measuring all-new sockets.
                local red = assert(handler.get_redcon()); red:close()
            end
            local started = now()
            for index = 1, iterations do
                local before = now()
                local red = assert(handler.get_redcon())
                if red:get_reused_times() > 0 then reused = reused + 1 end
                local pair = assert(functions[name](red))
                assert(pair.cert == cert .. '\n' .. cert and pair.pkey == key, 'benchmark returned incorrect credentials')
                if mode == 'fresh' then red:close() else handler.redis_keepalive(red) end
                samples[index] = now() - before
            end
            local elapsed = now() - started
            assert(mode ~= 'fresh' or reused == 0, 'fresh benchmark reused a connection')
            assert(mode ~= 'pooled' or reused >= iterations - 1, 'pooled benchmark did not reuse its connections')
            table.sort(samples)
            results[#results + 1] = {query = name, connections = mode, iterations = iterations,
                median_us = samples[math.ceil(iterations * .5)], p95_us = samples[math.ceil(iterations * .95)],
                total_ms = elapsed / 1000, operations_per_second = iterations / elapsed * 1000000,
                reused = reused, new_connections = iterations - reused}
        end
    end
end)
connection = assert(handler.get_redcon()); connection:del(unpack(keys)); connection:close()
assert(ok, err)
print(assert(require('cjson.safe').encode({results = results, server_info = info,
    nginx_version = ngx.config.nginx_version, ngx_lua_version = ngx.config.ngx_lua_version,
    certificate_bytes = #cert, private_key_bytes = #key, clock = 'CLOCK_MONOTONIC'})))
