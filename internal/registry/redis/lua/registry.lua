-- ARGV = [current time in seconds, ttl in seconds, services ...]
local current_time = ARGV[1]
local ttl = ARGV[2]

-- update the service list
for i = 3, #ARGV, 1 do
    redis.call('HSET', KEYS[1], ARGV[i], current_time + ttl)
end

-- retrieve all the services, removing any that have expired
local svcs = {}
local kvs = redis.call('HGETALL', KEYS[1])
for i = 1, #kvs, 2 do
    if kvs[i + 1] < current_time then
        redis.call('HDEL', KEYS[1], kvs[i])
    else
        table.insert(svcs, kvs[i])
    end
end
return svcs
