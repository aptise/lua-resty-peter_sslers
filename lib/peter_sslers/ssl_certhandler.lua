-- The includes
-- we may not need resty.http, but including it here is better for memory if we need it
local cjson_safe = require "cjson.safe"
local lrucache = require "resty.lrucache"
local redis = require "resty.redis"
local ssl = require "ngx.ssl"

-- this is the pintsized library
local http = require "resty.http"

-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
-- alias functions
local cjson_safe_decode = cjson_safe.decode
local cjson_null = cjson_safe.null
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
function initialize_worker(_cert_cache_duration, _lru_cache_duration, _lru_maxitems)
    ngx_log(ngx_NOTICE, "ssl_certhandler.initialize_worker")
    
    -- copy overrides
    cert_cache_duration = _cert_cache_duration or cert_cache_duration
    lru_cache_duration = _lru_cache_duration or lru_cache_duration
    lru_maxitems = _lru_maxitems or lru_maxitems
    
    ngx_log(ngx_NOTICE, "ssl_certhandler.initialize_worker | cert_cache_duration ", cert_cache_duration)
    ngx_log(ngx_NOTICE, "ssl_certhandler.initialize_worker | lru_maxitems ", lru_maxitems)
    ngx_log(ngx_NOTICE, "ssl_certhandler.initialize_worker | lru_cache_duration ", lru_cache_duration)

	-- init the cache
	cert_lrucache = lrucache.new(lru_maxitems) 
	if not cert_lrucache then
		return error("failed to create the cache: " .. (err or "unknown"))
	end
	return true
end


-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
-- START: these are just some helper functions



function certificate_pairing()
	-- simple container
	local pairing = {}
		  pairing["cert"] = nil
	 	  pairing["pkey"] = nil
	return pairing
end


function certificate_pairing_validate(cert)
	-- returns true or false based on the validity of a certificate_pairing
	if cert ~= nil and cert['cert'] ~= nil and cert['pkey'] ~= nil then
		return true
	end
	return false
end

function has_certificate_failmarker(cert)
	-- returns true if failmarker is present
    if cert['cert'] == 'x' or cert['pkey'] == 'x' then
		return true
    end
    return false
end


function certificate_pairing_pem_to_cdata(certificate_pem, certificate_cdata)
	certificate_cdata['cert'] = ssl_parse_pem_cert(certificate_pem['cert'])
	certificate_cdata['pkey'] = ssl_parse_pem_priv_key(certificate_pem['pkey'])
	return certificate_cdata
end

-- function certificate_pairing_pem_to_der(certificate_pem, certificate_der)
--	certificate_der['cert'] = ssl_cert_pem_to_der(certificate_pem['cert'])
--	certificate_der['pkey'] = ssl_priv_key_pem_to_der(certificate_pem['pkey'])
--	return certificate_der
-- end


function set_failmarker_sharedcache(server_name)
	local success, err, forcible = cert_cache:set(server_name .. ":c", 'x', cert_cache_duration)
	local success, err, forcible = cert_cache:set(server_name .. ":k", 'x', cert_cache_duration)
end


function set_failmarker_lrucache(server_name)
	-- the `lru:set` functions don't have a return value
	cert_lrucache:set(server_name .. ":c", 'x', lru_cache_duration)
	cert_lrucache:set(server_name .. ":k", 'x', lru_cache_duration)
end


function set_cert_lrucache(server_name, certificate_cdata)
	-- Add key and cert to the worker's LRU cache 
	ngx_log(ngx_DEBUG, "Caching cert & key cdata into the worker >")
	-- these 'set' functions don't have a return value
	cert_lrucache:set(server_name .. ":c", certificate_cdata['cert'], lru_cache_duration)
	cert_lrucache:set(server_name .. ":k", certificate_cdata['pkey'], lru_cache_duration)
	ngx_log(ngx_DEBUG, "< success")
end


function set_cert_sharedcache(server_name, certificate_pem)
	-- Add key and cert to the SHARED cache
	ngx_log(ngx_DEBUG, "Caching PEM cert & key into the shared cache >")
	-- these 'set' functions have a return value
	local success, err, forcible = cert_cache:set(server_name .. ":c", certificate_pem['cert'], cert_cache_duration)
	ngx_log(ngx_DEBUG, "Caching certificate_pem[cert] | success: ", success, " Err: ",  err)
	local success, err, forcible = cert_cache:set(server_name .. ":k", certificate_pem['pkey'], cert_cache_duration)
	ngx_log(ngx_DEBUG, "Caching certificate_pem[pkey] | success: ", success, " Err: ",  err)
	ngx_log(ngx_DEBUG, "< success")
end


function get_cert_lrucache(server_name)
	-- this is a cdata certificate
    local certificate_cdata = certificate_pairing()
    certificate_cdata['cert'] = cert_lrucache:get(server_name .. ":c")
    certificate_cdata['pkey'] = cert_lrucache:get(server_name .. ":k")
    return certificate_cdata
end

function get_cert_sharedcache(server_name)
	-- this is a PEM certificate
	local certificate_pem = certificate_pairing()
	certificate_pem['cert'] = cert_cache:get(server_name .. ":c")
	certificate_pem['pkey'] = cert_cache:get(server_name .. ":k")
    return certificate_pem
end



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
	-- returns `certificate_pairing()` or `nil`
    -- If the cert isn't in the cache, attept to retrieve from Redis
    local key_domain = "d:" .. _server_name
    local domain_data, err = redcon:hmget(key_domain, 'c', 'p', 'i')
    if domain_data == nil then
        ngx_log(ngx_DEBUG, "`nil` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil
    end
    if domain_data == ngx_null then
        ngx_log(ngx_DEBUG, "`ngx_null` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil
    end    
    -- ngx_log(ngx_DEBUG, 'err ', err)
    -- ngx_log(ngx_DEBUG, 'domain_data ', tostring(domain_data))

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
        ngx_log(ngx_DEBUG, "`id_cert == ngx_null or id_pkey == ngx_null or id_cacert == ngx_null for domain(", key_domain, ")")
        return nil
    end
    
    local pkey, err = redcon:get('p'..id_pkey)
    if pkey == nil then
        ngx_log(ngx_DEBUG, "failed to retreive pkey (", id_pkey, ") for domain (", key_domain, ") Err: ", err)
        return nil
    end

    local cert, err = redcon:get('c'..id_cert)
    if cert == nil or cert == ngx_null then
        ngx_log(ngx_DEBUG, "failed to retreive certificate (", id_cert, ") for domain (", key_domain, ") Err: ", err)
        return nil
    end

    local cacert, err = redcon:get('i'..id_cacert)
    if cacert == nil or cacert == ngx_null then
        ngx_log(ngx_DEBUG, "failed to retreive ca certificate (", id_cacert, ") for domain (", key_domain, ") Err: ", err)
        return nil
    end
    
    local certificate_pem = certificate_pairing()
		  certificate_pem['cert'] = cert.."\n"..cacert
		  certificate_pem['pkey'] = pkey
    return certificate_pem
end


function prime_2__query_redis(redcon, _server_name)
	-- returns `certificate_pairing()` or `nil`
    -- If the cert isn't in the cache, attept to retrieve from Redis
    local key_domain = _server_name
    local domain_data, err = redcon:hmget(key_domain, 'p', 'f')
    if domain_data == nil then
        ngx_log(ngx_DEBUG, "`nil` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil
    end
    if domain_data == ngx_null then
        ngx_log(ngx_DEBUG, "`ngx_null` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil
    end    

    local pkey = domain_data[1]
    local fullchain = domain_data[2]

    if pkey == ngx_null or fullchain == ngx_null then
        ngx_log(ngx_DEBUG, "`pkey == ngx_null or fullchain == ngx_null for domain(", key_domain, ")")
        return nil
    end
    
    local certificate_pem = certificate_pairing()
		  certificate_pem['cert'] = fullchain
		  certificate_pem['pkey'] = pkey
    return certificate_pem
end


function query_api_upstream(fallback_server, server_name)
	-- returns `certificate_pairing()` or `nil`
    local cert, pkey
    local httpc = http_new()

    local data_uri = fallback_server.."/domain/"..server_name.."/config.json?openresty=1"
    ngx_log(ngx_DEBUG, "querysing upstream API server at: ", data_uri)
    local response, err = httpc:request_uri(data_uri, {method = "GET", })

    if not response then
        ngx_log(ngx_ERR, 'API upstream - no response')
    else 
        local status = response.status
        -- local headers = response.headers
        -- local body = response.body
        if status == 200 then
            local body_value, err = cjson_safe_decode(response.body)
            if body_value ~= nil then
				-- prefer the multi
				if body_value['server_certificate__latest_multi'] ~= cjson_null then
					cert = body_value['server_certificate__latest_multi']['fullchain']['pem']
					pkey = body_value['server_certificate__latest_multi']['private_key']['pem']
				elseif body_value['server_certificate__latest_single'] ~= cjson_null then
					cert = body_value['server_certificate__latest_single']['fullchain']['pem']
					pkey = body_value['server_certificate__latest_single']['private_key']['pem']
				end
			end
        elseif status == 404 then
	        ngx_log(ngx_DEBUG, "API upstream 404 for: ", server_name)
            local body_value, err = cjson_safe_decode(response.body)
            if body_value ~= nil then
            	-- we expect a 'message' field
			    ngx_log(ngx_DEBUG, "API upstream error: ", body_value['message'])
            end
        else
            ngx_log(ngx_ERR, 'API upstream - bad response: ', status)
        end
    end
    
    if cert ~= nil and key ~= nil then
        ngx_log(ngx_DEBUG, "API upstream HIT for: ", server_name)
    else
        ngx_log(ngx_DEBUG, "API upstream MISS for: ", server_name)
    end

    local certificate_pem = certificate_pairing()
		  certificate_pem['cert'] = cert
		  certificate_pem['pkey'] = pkey
    return certificate_pem
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
        ngx_log(ngx_DEBUG, "SNI Not present - performing IP lookup ")
    
        -- don't bother with IP lookups
        -- exit out and just fall back on the default ssl cert
        return
    end 
    ngx_log(ngx_DEBUG, "SNI Lookup for: ", server_name)
    
    -- check worker lru cache first
    -- this stashes an actual cert
    local certificate_cdata = get_cert_lrucache(server_name)

	-- used for fallbacks
    local certificate_pem = nil
    
    if certificate_pairing_validate(certificate_cdata) then
        ngx_log(ngx_DEBUG, "cert_lrucache HIT for: ", server_name)
        if has_certificate_failmarker(certificate_cdata) then
            ngx_log(ngx_DEBUG, "Previously seen unsupported domain")
            -- don't bother with IP lookups
            -- exit out and just fall back on the default ssl cert
            return
        end
    else
    	-- now we check the fallback system

		-- check the nginx shared cache for certficate
    	certificate_pem = get_cert_sharedcache(server_name)
		if certificate_pairing_validate(certificate_pem) then
			ngx_log(ngx_DEBUG, "shared `cert_cache` HIT for: ", server_name)
	        if has_certificate_failmarker(certificate_pem) then
				ngx_log(ngx_DEBUG, "Previously seen unsupported domain in ngx.shared.DICT")
				-- cache onto the worker's lru cache
				set_failmarker_lrucache(server_name)

				-- don't bother with more lookups; exit out to nginx and just fall back on the default ssl cert
				return
			end
		else
			ngx_log(ngx_DEBUG, "shared `cert_cache` MISS for: ", server_name)

			-- our upstream providers will return a `certificate_pairing()` or `nil` value
			-- certificate_pem will be our main focus
		
			if prime_method ~= nil then
				-- ok, try to get it from redis
				ngx_log(ngx_DEBUG, "Redis: lookup enabled")
			
				local allowed_prime_methods = {1, 2, }
				if not allowed_prime_methods[prime_method] then
					ngx_log(ngx_ERR, "Redis: invalid `prime_method` not (1, 2) is `", prime_method, "`")
					return
				end

				-- grab redis connection
				local redcon, err = get_redcon()
				if redcon == nil then
					ngx_log(ngx_ERR, "Redis: could not get connection")
					-- exit out and just fall back on the default ssl cert
					return
				end

				-- actually query redis
				if prime_method == 1 then
					certificate_pem = prime_1__query_redis(redcon, server_name)
				elseif prime_method == 2 then
					certificate_pem = prime_2__query_redis(redcon, server_name)
				end

				-- return the redcon to the connection pool
				redis_keepalive(redcon)
			end

			-- use a fallback search?
			if fallback_server ~= nil then
				if not certificate_pairing_validate(certificate_pem) then
					ngx_log(ngx_DEBUG, "Upstream API: lookup enabled")
					certificate_pem = query_api_upstream(fallback_server, server_name)
				end
			end

			-- after all that work, if we finally have PEM...
			-- cache it!
			if certificate_pairing_validate(certificate_pem) then
				set_cert_sharedcache(server_name, certificate_pem)
			else
				ngx_log(ngx_DEBUG, "Failed to retrieve PEM for ", server_name)

				-- set a fail marker - SHARED cache
				set_failmarker_sharedcache(server_name)

				-- set a fail marker - WORKER cache
				set_failmarker_lrucache(server_name)

				-- exit out and just fall back on the default ssl cert
				return
			end
		end

		-- at this point we have a valid PEM
		-- if certificate_pairing_validate(certificate_pem) then
		-- end

		-- convert from PEM to cdata for WORKER cache (and this server!)
		certificate_cdata = certificate_pairing_pem_to_cdata(certificate_pem, certificate_cdata)
		set_cert_lrucache(server_name, certificate_cdata)
    end

    if certificate_pairing_validate(certificate_cdata) then
		-- since we have a certs for this server, now we can continue...
		ssl_clear_certs()

		-- Set cert
		local ok, err = ssl_set_cert(certificate_cdata['cert'])
		if not ok then
			ngx_log(ngx_ERR, "failed to set ssl certificate: ", server_name, " ", err)
			return
		else
			ngx_log(ngx_DEBUG, "set ssl certificate: ", server_name)
		end

		-- Set key
		local ok, err = ssl_set_priv_key(certificate_cdata['pkey'])
		if not ok then
			ngx_log(ngx_ERR, "failed to set ssl private key: ", server_name, " ", err)
			return
		else
			ngx_log(ngx_DEBUG, "set ssl private key: ", server_name)
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