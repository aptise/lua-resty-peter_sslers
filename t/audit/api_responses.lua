-- Use the real JSON decoder and ngx.log; replace only the HTTP transport.
local cases = {
    invalid_json = {body = '{'},
    scalar = {body = 'true'},
    json_null = {body = 'null'},
    array = {body = '[]'},
    empty_object = {body = '{}'},
    incomplete = {body = '{"certificate_signed__latest_multi":{}}'},
    missing_preference = {body = '{"certificate_signed__latest_multi":null}'},
    wrong_type = {body = '{"certificate_signed__latest_multi":false,"certificate_signed__latest_single":null}'},
    error_response = {body = '{"result":"error","form_errors":{"domain_name":"invalid"},"certificate_signed__latest_multi":null,"certificate_signed__latest_single":null}'},
    explicit_absence = {body = '{"certificate_signed__latest_multi":null,"certificate_signed__latest_single":null}', absent = true},
    not_found_metadata = {status = 404, body = '{"message":{"unexpected":"object"}}', absent = true},
}

return function(case)
    local json = require 'cjson.safe'
    local fixture = cases[case]
    if case == 'success_metadata' or case == 'fallback_preference' then
        local valid = {fullchain = {pem = 'cert'}, private_key = {pem = 'key'}}
        fixture = {cert = true, body = assert(json.encode({
            certificate_signed__latest_multi = case == 'fallback_preference' and {} or valid,
            certificate_signed__latest_single = valid,
            result = {unexpected = 'object'}, notes = {unexpected = 'array'},
        }))}
    end
    assert(fixture, 'unknown API response test')
    local saved_http = package.loaded['resty.http']
    package.loaded['resty.http'] = {new = function() return {
        request_uri = function() return {status = fixture.status or 200, body = fixture.body} end,
    } end}
    local ok, err = pcall(function()
        local handler = assert(loadfile('lib/resty/peter_sslers.lua'))()
        local pair = handler.query_api_upstream('http://backend', 'test.example.com')
        if fixture.cert then
            assert(pair.cert == 'cert' and pair.pkey == 'key', 'valid candidate must survive unexpected metadata')
            assert(not pair.transient, 'valid candidate is not a transient error')
        elseif fixture.absent then
            assert(not pair.cert and not pair.pkey, 'absence must not return credentials')
            assert(not pair.transient, 'explicit absence must remain eligible for negative caching')
        else
            assert(not pair.cert and not pair.pkey, 'malformed response must not return credentials')
            assert(pair.transient, 'malformed response must allow backend recovery')
        end
    end)
    package.loaded['resty.http'] = saved_http
    assert(ok, err)
end
