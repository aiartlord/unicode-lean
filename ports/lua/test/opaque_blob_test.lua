local h = require("test_helper")
local blob = require("unicode_lua.opaque_blob")
local validated = require("unicode_lua.validated_utf8")

-- Utf8Blob / ValidatedUtf8 refinement-type tests. Byte sequences are
-- 1-indexed tables of integers in this port.

h.assert_equal(true, blob.is_utf8_blob({ 0x48, 0x69 }), "blob ascii")
h.assert_equal(true, blob.is_utf8_blob({ 0xC3, 0xA9 }), "blob 2byte")
h.assert_equal(true, blob.is_utf8_blob({ 0xF0, 0x9F, 0x98, 0x80 }), "blob 4byte")
h.assert_equal(false, blob.is_utf8_blob({ 0xC0, 0x80 }), "blob overlong")
h.assert_equal(false, blob.is_utf8_blob({ 0xED, 0xA0, 0x80 }), "blob surrogate")

local within = blob.of({ 0x48, 0x69 }, 16)
if within == nil then
  error("blob.of within bound returned nil")
end
h.assert_equal(16, within.max_bytes, "blob max_bytes")
h.assert_equal(2, #within.value, "blob value length")
h.assert_equal(nil, blob.of({ 0x48, 0x69, 0x21 }, 2), "blob over bound")
h.assert_equal(nil, blob.of({ 0xC0, 0x80 }, 16), "blob malformed")
if blob.of({}, 32) == nil then
  error("blob.of empty under any bound returned nil")
end

local v = validated.validate({ 0xC3, 0xA9 })
if v == nil then
  error("validate rejected valid input")
end
h.assert_equal(2, #validated.as_bytes(v), "validated as_bytes length")
h.assert_equal(0xC3, validated.unwrap(v)[1], "validated unwrap byte 1")
h.assert_equal(nil, validated.validate({ 0xED, 0xA0, 0x80 }), "validated rejects malformed")
