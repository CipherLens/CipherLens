local openssl = require("openssl")
local mac = assert(openssl.mac, "openssl.mac table not found")

local function hex(s)
  if s == nil then return "nil" end
  return (s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

local key = string.rep(string.char(0x11), 16)

local ctx = assert(mac.ctx("aes-128-cbc", key), "mac.ctx failed")

local ok1 = ctx:update("authorized-prefix")
local tag1 = ctx:final(true)

local tag2 = ctx:final("post-final-data", true)

print("library=lua-openssl")
print("linked_openssl=3.5.5-static")
print("algorithm=CMAC-AES-128-CBC")
print("update1=" .. tostring(ok1))
print("tag1_len=" .. tostring(tag1 and #tag1 or "nil"))
print("tag1=" .. hex(tag1))
print("final_with_post_final_data_tag2_len=" .. tostring(tag2 and #tag2 or "nil"))
print("tag2=" .. hex(tag2))
print("tag1_eq_tag2=" .. tostring(tag1 == tag2))

if tag2 then
  print("application_decision=APPLICATION_ACCEPTED_FINAL_WITH_POST_FINAL_DATA")
else
  print("application_decision=APPLICATION_REJECT")
end
