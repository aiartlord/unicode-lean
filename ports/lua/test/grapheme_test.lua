-- UAX #29 grapheme cluster segmentation tests.
--
-- Mirrors the Rust port's targeted vectors (ports/rust/tests/segmentation.rs)
-- and then validates the segmentation against every row of the bundled
-- GraphemeBreakTest.txt conformance corpus (testdata/GraphemeBreakTest.txt).

local h = require("test_helper")
local grapheme = require("unicode_lua.segmentation.grapheme")

-- Boundary markers in GraphemeBreakTest.txt, as raw UTF-8 bytes so the parse is
-- independent of the source file's own encoding:
--   DIVIDE (U+00F7 "÷") = 0xC3 0xB7  -> break
--   MULTIPLY (U+00D7 "×") = 0xC3 0x97 -> no break
local DIV = "\195\183"
local MUL = "\195\151"

-- // targeted vectors // -----------------------------------------------------

-- "abc": break before each + eot.
h.assert_equal(
  grapheme.grapheme_breaks({ 0x61, 0x62, 0x63 }),
  { true, true, true, true },
  "ascii each its own cluster"
)
h.assert_equal(#grapheme.grapheme_clusters({ 0x61, 0x62, 0x63 }), 3, "ascii cluster count")

-- e + COMBINING ACUTE (U+0301) is one cluster (GB9).
h.assert_equal(
  grapheme.grapheme_breaks({ 0x65, 0x0301 }),
  { true, false, true },
  "combining mark joins"
)
h.assert_equal(#grapheme.grapheme_clusters({ 0x65, 0x0301 }), 1, "combining mark cluster count")

-- CR LF is a single cluster (GB3).
h.assert_equal(
  grapheme.grapheme_breaks({ 0x0D, 0x0A }),
  { true, false, true },
  "crlf is one cluster"
)

-- Regional indicators 🇯🇵 (U+1F1EF U+1F1F5) form one cluster (GB12).
h.assert_equal(
  grapheme.grapheme_breaks({ 0x1F1EF, 0x1F1F5 }),
  { true, false, true },
  "flag pair is one cluster"
)
h.assert_equal(#grapheme.grapheme_clusters({ 0x1F1EF, 0x1F1F5 }), 1, "flag pair cluster count")

-- Four regional indicators = two flags = two clusters (GB12/13 parity).
h.assert_equal(
  #grapheme.grapheme_clusters({ 0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8 }),
  2,
  "four flags are two clusters"
)

-- 👨‍👩‍👧 : man ZWJ woman ZWJ girl is one cluster (GB11).
h.assert_equal(
  #grapheme.grapheme_clusters({ 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467 }),
  1,
  "emoji zwj sequence is one cluster"
)

-- // full conformance corpus // ----------------------------------------------

local function parse_line(line)
  -- Drop the trailing comment, then split on whitespace into markers and hex
  -- code points. Markers and code points strictly alternate, starting and
  -- ending with a marker.
  local hash = line:find("#", 1, true)
  local body = hash and line:sub(1, hash - 1) or line
  local expected = {}
  local cps = {}
  for tok in body:gmatch("%S+") do
    if tok == DIV then
      expected[#expected + 1] = true
    elseif tok == MUL then
      expected[#expected + 1] = false
    else
      local cp = tonumber(tok, 16)
      if cp == nil then
        error("grapheme conformance: unparseable token '" .. tok .. "'")
      end
      cps[#cps + 1] = cp
    end
  end
  return cps, expected
end

local f = assert(io.open("testdata/GraphemeBreakTest.txt", "r"))
local rows = 0
local lineno = 0
for line in f:lines() do
  lineno = lineno + 1
  local trimmed = line:gsub("^%s+", ""):gsub("%s+$", "")
  if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" then
    local cps, expected = parse_line(line)
    if #expected ~= #cps + 1 then
      error(
        "grapheme conformance line "
          .. lineno
          .. ": expected "
          .. (#cps + 1)
          .. " boundary markers, got "
          .. #expected
      )
    end
    local actual = grapheme.grapheme_breaks(cps)
    h.assert_equal(actual, expected, "GraphemeBreakTest line " .. lineno)
    rows = rows + 1
  end
end
f:close()

if rows == 0 then
  error("grapheme conformance: no data rows parsed from GraphemeBreakTest.txt")
end

print("grapheme: validated " .. rows .. " GraphemeBreakTest rows")
