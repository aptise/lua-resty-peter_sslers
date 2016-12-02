-- The includes
-- we may not need resty.http, but including it here is better for memory if we need it
local cjson = require "cjson"
local lrucache = require "resty.lrucache"
local redis = require "resty.redis"
local ssl = require "ngx.ssl"

-- this is the pintsized library
local http = require "resty.http"

-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
-- alias functions
local cjson_decode = cjson.decode
local cjson_null = cjson.null
local http_new = http.new
local ngx_DEBUG = ngx.DEBUG
local ngx_ERR = ngx.ERR
local ngx_log = ngx.log
local ngx_NOTICE = ngx.NOTICE
local ngx_null = ngx.null
local ngx_say = ngx.say
local ngx_var = ngx.var
local ssl_clear_certs = ssl.clear_certs
local ssl_server_name = ssl.server_name

-- these use nginx.shared.DICT to store PEM data across workers
local ssl_cert_pem_to_der = ssl.cert_pem_to_der
local ssl_priv_key_pem_to_der = ssl.priv_key_pem_to_der
local ssl_set_der_cert = ssl.set_der_cert
local ssl_set_der_priv_key = ssl.set_der_priv_key

-- these use cdata pointers, so must use lrucache to share within the worker
local ssl_parse_pem_cert = ssl.parse_pem_cert
local ssl_parse_pem_priv_key = ssl.parse_pem_priv_key
local ssl_set_cert = ssl.set_cert
local ssl_set_priv_key = ssl.set_priv_key

-- our caches
local cert_cache = ngx.shared.cert_cache

-- we need to initialize the cache on the lua module level so that
-- it can be shared by all the requests served by each nginx worker process:
-- note that this is a WORKER cache
local cert_lrucache = nil


-- cert_cache_duration is for the shared dict; misses fall back onto Redis/PeterSslers
-- cert_cache can be emptied via the api
local cert_cache_duration = 600
-- lru_cache_duration is for the unshared worker dict; misses fall back on cert_cache/Redis/PeterSslers
-- lru must timeout
local lru_cache_duration = 60
local lru_maxitems = 200  -- allow up to 200 items in the cache



function initialize()
    ngx_log(ngx_NOTICE, "ssl_certhandler.initialize")
    return true
end
function initialize_worker(_lru_cache_duration, _lru_maxitems)
    ngx_log(ngx_NOTICE, "ssl_certhandler.initialize_worker")
    
    -- copy overrides
    lru_cache_duration = _lru_cache_duration or lru_cache_duration
    lru_maxitems = _lru_maxitems or lru_maxitems
    
    ngx_log(ngx_ERR, "lru_maxitems ", lru_maxitems)
    ngx_log(ngx_ERR, "lru_cache_duration ", lru_cache_duration)

	-- init the cache
	cert_lrucache = lrucache.new(lru_maxitems) 
	if not cert_lrucache then
		return error("failed to create the cache: " .. (err or "unknown"))
	end
end


-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
-- START: these are just some helper functions


function get_redcon()
    -- this sets up our redis connection
    -- it checks to see if it is a pooled connection (ie, reused) and changes to db9 if it is new
    -- Setup Redis connection
    local redcon = redis:new()
    -- Connect to redis.  NOTE: this is a pooled connection
    local ok, err = redcon:connect("127.0.0.1", "6379")
    if not ok then
        ngx_log(ngx_ERR, "REDIS: Failed to connect to redis: ", err)
        return nil, err
    end
    -- Change the redis DB to #9
    -- We only have to do this on new connections
    local times, err = redcon:get_reused_times()
    if times <= 0 then
        ngx_log(ngx_NOTICE, "changing to db 9: ", times)
        redcon:select(9)
    end
    return redcon
end


function redis_keepalive(redcon)
    -- put `redcode` into the connection pool
    -- * pool size = 100
    -- * idle time = 10s
    -- note: this will close the connection
    local ok, err = redcon:set_keepalive(10000, 100)
    if not ok then
        ngx_log(ngx_ERR, "failed to set keepalive: ", err)
        return
    end
end


function prime_1__query_redis(redcon, _server_name)
    -- If the cert isn't in the cache, attept to retrieve from Redis
    local key_domain = "d:" .. _server_name
    local domain_data, err = redcon:hmget(key_domain, 'c', 'p', 'i')
    if domain_data == nil then
        ngx_log(ngx_NOTICE, "`nil` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
    end
    if domain_data == ngx_null then
        ngx_log(ngx_NOTICE, "`ngx_null` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
    end    
    -- ngx_log(ngx_NOTICE, 'err ', err)
    -- ngx_log(ngx_NOTICE, 'domain_data ', tostring(domain_data))

    -- lua arrays are 1 based!
    local id_cert = domain_data[1]
    local id_pkey = domain_data[2]
    local id_cacert = domain_data[3]
	
	-- conditional logging
	-- ngx_log(ngx_DEBUG, "prime_1__query_redis")
	-- ngx_log(ngx_DEBUG, "id_cert ", id_cert)
	-- ngx_log(ngx_DEBUG, "id_pkey ", id_pkey)
	-- ngx_log(ngx_DEBUG, "id_cacert ", id_cacert)
    
    if id_cert == ngx_null or id_pkey == ngx_null or id_cacert == ngx_null then
        ngx_log(ngx_NOTICE, "`id_cert == ngx_null or id_pkey == ngx_null or id_cacert == ngx_null for domain(", key_domain, ")")
        return nil, nil
    end
    
    local pkey, err = redcon:get('p'..id_pkey)
    if pkey == nil then
        ngx_log(ngx_NOTICE, "failed to retreive pkey (", id_pkey, ") for domain (", key_domain, ") Err: ", err)
        return nil, nil
    end

    local cert, err = redcon:get('c'..id_cert)
    if cert == nil or cert == ngx_null then
        ngx_log(ngx_NOTICE, "failed to retreive certificate (", id_cert, ") for domain (", key_domain, ") Err: ", err)
        return nil, nil
    end

    local cacert, err = redcon:get('i'..id_cacert)
    if cacert == nil or cacert == ngx_null then
        ngx_log(ngx_NOTICE, "failed to retreive ca certificate (", id_cacert, ") for domain (", key_domain, ") Err: ", err)
        return nil, nil
    end
    
    local fullchain = cert.."\n"..cacert
    return fullchain, pkey
end


function prime_2__query_redis(redcon, _server_name)
    -- If the cert isn't in the cache, attept to retrieve from Redis
    local key_domain = _server_name
    local domain_data, err = redcon:hmget(key_domain, 'p', 'f')
    if domain_data == nil then
        ngx_log(ngx_NOTICE, "`nil` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
    end
    if domain_data == ngx_null then
        ngx_log(ngx_NOTICE, "`ngx_null` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
    end    

    local pkey = domain_data[1]
    local fullchain = domain_data[2]

    if pkey == ngx_null or fullchain == ngx_null then
        ngx_log(ngx_NOTICE, "`pkey == ngx_null or fullchain == ngx_null for domain(", key_domain, ")")
        return nil, nil
    end
    
    return fullchain, pkey
end


function query_api_upstream(fallback_server, server_name)
    
    local cert, key

    local httpc = http_new()

    local data_uri = fallback_server.."/.well-known/admin/domain/"..server_name.."/config.json?openresty=1"
    ngx_log(ngx_NOTICE, "querysing upstream API server at: ", data_uri)
    local response, err = httpc:request_uri(data_uri, {method = "GET", })

    if not response then
        ngx_log(ngx_NOTICE, 'API upstream - no response')
    else 
        local status = response.status
        -- local headers = response.headers
        -- local body = response.body
        if status == 200 then
            local body_value = cjson_decode(response.body)
            -- prefer the multi
            if body_value['server_certificate__latest_multi'] ~= cjson_null then
                cert = body_value['server_certificate__latest_multi']['fullchain']['pem']
                key = body_value['server_certificate__latest_multi']['private_key']['pem']
            elseif body_value['server_certificate__latest_single'] ~= cjson_null then
                cert = body_value['server_certificate__latest_single']['fullchain']['pem']
                key = body_value['server_certificate__latest_single']['private_key']['pem']
            end
        else
            ngx_log(ngx_NOTICE, 'API upstream - bad response: ', status)
        end
    end
    if cert ~= nil and key ~= nil then
        ngx_log(ngx_NOTICE, "API cache HIT for: ", server_name)
    else
        ngx_log(ngx_NOTICE, "API cache MISS for: ", server_name)
    end
    return cert, key
end


-- END helper functions
-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~

-- =============================================================================

-- START MAIN LOGIC

function set_ssl_certificate(prime_method, fallback_server)

	-- cache the cdata certs for no more than 60s
	-- these are PER-WORKER, and may stick around for this long after an update/expire

    local server_name = ssl_server_name()

    -- Check for SNI request.
    if server_name == nil then
        ngx_log(ngx_NOTICE, "SNI Not present - performing IP lookup ")
    
        -- don't bother with IP lookups
        -- exit out and just fall back on the default ssl cert
        return
    end 
    ngx_log(ngx_NOTICE, "SNI Lookup for: ", server_name)
    
    -- check worker lru cache first
    -- this stashes an actual cert
    local cert_cdata = cert_lrucache:get(server_name .. ":c")
    local key_cdata = cert_lrucache:get(server_name .. ":k")
    
    -- this is a fallback
    local cert_der = nil
    local key_der = nil

    if cert_cdata ~= nil and key_cdata ~= nil then
        ngx_log(ngx_NOTICE, "cert_lrucache HIT for: ", server_name)
        if cert == 'x' or key == 'x' then
            ngx_log(ngx_NOTICE, "Previously seen unsupported domain")
            -- don't bother with IP lookups
            -- exit out and just fall back on the default ssl cert
            return
        end
    else
    	-- now we check the fallback system

		-- Check cache for certficate
		local cert_pem = cert_cache:get(server_name .. ":c")
		local key_pem = cert_cache:get(server_name .. ":k")
		if cert_pem ~= nil and key_pem ~= nil then
			ngx_log(ngx_NOTICE, "shared `cert_cache` HIT for: ", server_name)
			if cert == 'x' or key == 'x' then
				ngx_log(ngx_NOTICE, "Previously seen unsupported domain; pem")

				-- cache onto the worker's lru cache
				-- this doesn't have a return value
				cert_lrucache:set(server_name .. ":c", 'x', lru_cache_duration)
				cert_lrucache:set(server_name .. ":k", 'x', lru_cache_duration)

				-- don't bother with more lookups
				-- exit out and just fall back on the default ssl cert
				return
			end
		else
			ngx_log(ngx_NOTICE, "shared `cert_cache` MISS for: ", server_name)
		
			if prime_method ~= nil then
				-- ok, try to get it from redis
				ngx_log(ngx_NOTICE, "Redis: lookup enabled")
			
				local allowed_prime_methods = {1, 2, }
				if not allowed_prime_methods[prime_method] then
					ngx_log(ngx_NOTICE, "Redis: invalid `prime_method` not (1, 2) is `", prime_method, "`")
					return
				end

				-- grab redis connection
				local redcon, err = get_redcon()
				if redcon == nil then
					ngx_log(ngx_NOTICE, "Redis: could not get connection")

					-- exit out and just fall back on the default ssl cert
					return
				end

				-- actually query redis
				if prime_method == 1 then
					cert_pem, key_pem = prime_1__query_redis(redcon, server_name)
				elseif prime_method == 2 then
					cert_pem, key_pem = prime_2__query_redis(redcon, server_name)
				end

				-- return the redcon to the connection pool
				redis_keepalive(redcon)
			end

			-- let's use a fallback search
			if cert_pem == nil or key_pem == nil then
				if fallback_server ~= nil then
					ngx_log(ngx_NOTICE, "Upstream API: lookup enabled")
					cert_pem, key_pem = query_api_upstream(fallback_server, server_name)
				end
			end

			if cert_pem ~= nil and key_pem ~= nil then 

				-- Add key and cert to the SHARED cache 
				local success, err, forcible = cert_cache:set(server_name .. ":c", cert_pem)
				ngx_log(ngx_DEBUG, "Caching cert_pem| success: ", success, " Err: ",  err)
				local success, err, forcible = cert_cache:set(server_name .. ":k", key_pem)
				ngx_log(ngx_DEBUG, "Caching key_pem | success: ", success, " Err: ",  err)

			end


		end
		
		-- we are still in a PEM block, but this could come from anywhere

		if cert_pem ~= nil and key_pem ~= nil then 

			-- convert from PEM to cdata for WORKER cache
			cert_cdata = ssl_parse_pem_cert(cert_pem)
			key_cdata = ssl_parse_pem_priv_key(key_pem)

			-- Add key and cert to the cache 
			-- this doesn't have a return value
			ngx_log(ngx_DEBUG, "Caching cert & key cdata into the worker >")
			cert_lrucache:set(server_name .. ":c", cert_cdata, lru_cache_duration)
			cert_lrucache:set(server_name .. ":k", key_cdata, lru_cache_duration)
			ngx_log(ngx_DEBUG, "< success")

		else     
			ngx_log(ngx_NOTICE,
					"Failed to retrieve " .. (cert and "" or "cert ") ..  (key and "" or "key "),
					"for ",
					server_name
					)

			-- set a fail marker - SHARED cache
			local success, err, forcible = cert_cache:set(server_name .. ":c", 'x', cert_cache_duration)
			local success, err, forcible = cert_cache:set(server_name .. ":k", 'x', cert_cache_duration)

			-- set a fail marker - WORKER cache
			cert_lrucache:set(server_name .. ":c", 'x', lru_cache_duration)
			cert_lrucache:set(server_name .. ":k", 'x', lru_cache_duration)

			-- exit out and just fall back on the default ssl cert
			return
		end
    
    end

    if cert_cdata ~= nil and key_cdata ~= nil then
		-- since we have a certs for this server, now we can continue...
		ssl_clear_certs()

		-- Set cert
		local ok, err = ssl_set_cert(cert_cdata)
		if not ok then
			ngx_log(ngx_ERR, "failed to set cert (cdata): ", err)
			return
		else
			ngx_log(ngx_DEBUG, "set cert (cdata)")
		end

		-- Set key
		local ok, err = ssl_set_priv_key(key_cdata)
		if not ok then
			ngx_log(ngx_ERR, "failed to set key (cdata): ", err)
			return
		else
			ngx_log(ngx_DEBUG, "set key (cdata)")
		end
	end
end


function status_ssl_certs()
    ngx.header.content_type = 'application/json'
    local prefix = ngx_var.location
	-- handmade json value    	
	ks = ''
	ks_valid = {}
	ks_invalid = {}
	-- max count is 1024, but specify it anyways
	local all_keys = cert_cache:get_keys(1024)
	
	-- `all_keys` is a table of (idx, key)
	for idx, k in pairs(all_keys) do
		_domain = k:sub(0,-3)
		_ext = k:sub(-2,-1)
		-- each domain has a duplicate on "{DOMAIN}:k" and "{DOMAIN}:v"
		-- we only need one
		if _ext == ':c' then
			v = cert_cache:get(k)
			-- ngx_log(ngx_DEBUG, "idx ", idx)
			-- ngx_log(ngx_DEBUG, "k ", k)
			-- ngx_log(ngx_DEBUG, "_domain ", _domain)
			-- ngx_log(ngx_DEBUG, "_ext ", _ext)
			-- ngx_log(ngx_DEBUG, "v ", v)
			if v == 'x' then
				table.insert(ks_invalid, _domain)
			else
				table.insert(ks_valid, _domain)
			end
		end
	end

	_ks_valid = ''
	for idx, k in pairs(ks_valid) do
		_ks_valid = _ks_valid .. '"' .. k .. '",'
	end
	-- remove the last ,
	_ks_valid = _ks_valid:sub(1, -2)

	_ks_invalid = ''
	-- `_ks_invalid` is a table of (idx, key)
	for idx, k in pairs(ks_invalid) do
		_ks_invalid = _ks_invalid .. '"' .. k .. '",'
	end
	-- remove the last ,
	_ks_invalid = _ks_invalid:sub(1, -2)
	ks = '{"valid": [' .. _ks_valid .. '], "invalid": [' .. _ks_invalid .. ']}'
	expiries = '{"ngx.shared.cert_cache": ' .. cert_cache_duration .. ', "resty.lrucache": ' .. lru_cache_duration .. '}'
	rval = '{"result": "success", "note": "This is a max(1024) listening of keys in the ngx.shared.DICT `cert_cache`. This does not show the worker\'s own LRU cache, or Redis.", "keys": ' .. ks .. ', "expiries": ' .. expiries .. "}"
	ngx_say(rval)
	return
end


function expire_ssl_certs()
    ngx.header.content_type = 'application/json'
    local prefix = ngx_var.location
    if ngx_var.request_uri == prefix..'/all' then
        cert_cache:flush_all()
        ngx_say('{"result": "success", "expired": "all"}')
        return
    end
    local _domain = string.match(ngx_var.request_uri, '^'..prefix..'/domain/([%w-.]+)$')  
    if _domain then
        cert_cache:delete(_domain)
        ngx_say('{"result": "success", "expired": "domain", "domain": "' .. _domain ..'"}')
        return
    end
    ngx_say('{"result": "error", "expired": "None", "reason": "Unknown URI"}')
    ngx.status = 404
    return
end


local _M = {get_redcon = get_redcon,
            redis_keepalive = redis_keepalive,
            prime_1__query_redis = prime_1__query_redis,
            prime_2__query_redis = prime_2__query_redis,
            query_api_upstream = query_api_upstream,
            set_ssl_certificate = set_ssl_certificate,
            expire_ssl_certs = expire_ssl_certs,
            status_ssl_certs = status_ssl_certs,

            initialize_worker = initialize_worker,
            initialize = initialize,
            }

return _M