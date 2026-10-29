-- Minimal mlcache contract for backend fault injection. Real storage, IPC,
-- serializers, and locking are exercised separately in t/cache and worker tests.
local dict = ngx.shared.cert_cache
local negative = {}
return {new = function(_, _, options)
    local cache = {lru = options.lru}
    local function serialize(value, opts)
        if value == nil then return negative end
        return (opts and opts.l1_serializer or options.l1_serializer)(value)
    end
    function cache:set(key, opts, value)
        local stored = value
        if value == nil then stored = false end
        local ok, err = dict:set(key .. ':pair', stored, options.ttl)
        if not ok then return nil, err end
        local converted, conversion_err = serialize(value, opts)
        if conversion_err then return nil, conversion_err end
        self.lru:set(key, converted, options.ttl)
        return true
    end
    function cache:get(key, opts, callback, ...)
        local value = self.lru:get(key)
        if value == negative then return nil, nil, 1 end
        if value ~= nil then return value, nil, 1 end
        value = dict:get(key .. ':pair')
        if value ~= nil then
            if value == false then
                self.lru:set(key, negative, options.neg_ttl)
                return nil, nil, 2
            end
            local converted, err = serialize(value, opts)
            if err then return nil, err end
            self.lru:set(key, converted, options.ttl)
            return converted, nil, 2
        end
        if not callback then return nil, nil, -1 end
        local ok, result, err, ttl = pcall(callback, ...)
        if not ok then return nil, result end
        if err then return nil, err end
        if ttl and ttl < 0 then return result, nil, 3 end
        local stored, store_err = self:set(key, opts, result)
        if not stored then return nil, store_err end
        value = self.lru:get(key)
        if value == negative then return nil, nil, 3 end
        return value, nil, 3
    end
    function cache:peek(key)
        local value = dict:get(key .. ':pair')
        if value == nil then return nil end
        if value == false then return options.neg_ttl, nil, nil end
        return options.ttl, nil, value
    end
    function cache:delete(key)
        dict:delete(key .. ':pair')
        self.lru:delete(key)
        return true
    end
    function cache:update() return true end
    return cache
end}
