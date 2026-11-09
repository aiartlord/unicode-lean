-- UAX #14 line breaking tests.
--
-- Targeted vectors pinning the individual rules and the output shape the Lean
-- `lineBreaks_length` theorem fixes, then the segmentation against every row of
-- the bundled LineBreakTest.txt conformance corpus
-- (testdata/LineBreakTest.txt).

local h = require("test_helper")
local line_break = require("unicode_lua.segmentation.line_break")
local tables = require("unicode_lua.segmentation.line_break_tables")

-- Boundary markers in LineBreakTest.txt, as raw UTF-8 bytes so the parse is
-- independent of the source file's own encoding:
--   DIVIDE (U+00F7 "÷") = 0xC3 0xB7  -> break
--   MULTIPLY (U+00D7 "×") = 0xC3 0x97 -> no break
local DIV = "\195\183"
local MUL = "\195\151"

-- // targeted vectors // -----------------------------------------------------

-- The Lean `lineBreaks_length` theorem: `#cps + 1` flags.
for length = 0, 7 do
  local cps = {}
  for i = 1, length do
    cps[i] = 0x60 + i
  end
  h.assert_equal(#line_break.line_breaks(cps), length + 1,
    "one flag per boundary at length " .. length)
end

-- LB2 forbids a break at the start of text; LB3 requires one at the end.
local ab = line_break.line_breaks({ 0x61, 0x62 })
h.assert_equal(ab[1], false, "start of text never breaks")
h.assert_equal(ab[#ab], true, "end of text always breaks")

-- LB28 keeps letters together; LB18 breaks after a space.
h.assert_equal(
  line_break.line_breaks({ 0x61, 0x62 }),
  { false, false, true },
  "a word is one run"
)
local spaced = line_break.line_runs({ 0x61, 0x20, 0x62 })
h.assert_equal(#spaced, 2, "a space opens the next run")
h.assert_equal(spaced[1], { 0x61, 0x20 }, "the space stays with the word before it")
h.assert_equal(spaced[2], { 0x62 }, "the next run starts after the space")

-- LB4: BK divides. U+000C FORM FEED is class BK.
h.assert_equal(
  line_break.line_breaks({ 0x61, 0x000C, 0x62 }),
  { false, false, true, true },
  "a mandatory break character breaks after itself"
)

-- LB5: CR times LF, then a mandatory break after the pair.
h.assert_equal(
  line_break.line_breaks({ 0x0D, 0x0A, 0x61 }),
  { false, false, true, true },
  "carriage return line feed is not split"
)

-- LB9: X CM behaves as X, so no break falls inside the pair.
h.assert_equal(
  line_break.line_breaks({ 0x61, 0x0301 }),
  { false, false, true },
  "a combining mark takes the class of its base"
)

-- LB11: before WJ and after WJ.
h.assert_equal(
  line_break.line_breaks({ 0x61, 0x2060, 0x62 }),
  { false, false, false, true },
  "a word joiner glues both sides"
)

-- LB15c: SP divides IS NU -- "a .35" breaks before the period.
h.assert_equal(
  line_break.line_breaks({ 0x61, 0x20, 0x2E, 0x33, 0x35 }),
  { false, false, true, false, false, true },
  "a space before a number opening period breaks"
)

-- LB25: "1,000" is one run across the SY separator.
h.assert_equal(
  #line_break.line_runs({ 0x31, 0x2C, 0x30, 0x30, 0x30 }),
  1,
  "a numeric chain holds together"
)

-- LB30a: an even-length RI run takes no break inside a pair, and a second pair
-- may start a new line.
h.assert_equal(
  line_break.line_breaks({ 0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8 }),
  { false, false, true, false, true },
  "regional indicators pair off"
)

-- LB30b: EB times EM.
h.assert_equal(
  line_break.line_breaks({ 0x1F466, 0x1F3FB }),
  { false, false, true },
  "an emoji modifier stays on its base"
)

-- LB1 resolves the tailorable classes into the working alphabet.
h.assert_equal(line_break.raw_class(0x3041), "Cj", "U+3041 is CJ")
h.assert_equal(line_break.resolved_class(0x3041), "Ns", "LB1 reads CJ as NS")
h.assert_equal(line_break.raw_class(0x00A7), "Ai", "U+00A7 is AI")
h.assert_equal(line_break.resolved_class(0x00A7), "Al", "LB1 reads AI as AL")
h.assert_equal(line_break.raw_class(0xD800), "Sg", "a surrogate is SG")
h.assert_equal(line_break.resolved_class(0xD800), "Al", "LB1 reads SG as AL")
-- U+05EB lies in the Hebrew block's unassigned gap, which no range covers, so
-- it takes the @missing XX default.
h.assert_equal(line_break.raw_class(0x05EB), "Xx", "an uncovered code point is XX")
h.assert_equal(line_break.resolved_class(0x05EB), "Al", "LB1 reads XX as AL")

-- LB1 resolves SA by General_Category: U+0E31 THAI CHARACTER MAI HAN-AKAT is SA
-- with category Mn, so LB1 reads it as CM; U+0E01 THAI CHARACTER KO KAI is SA
-- with category Lo, so LB1 reads it as AL.
h.assert_equal(line_break.raw_class(0x0E31), "Sa", "U+0E31 is SA")
h.assert_equal(line_break.resolved_class(0x0E31), "Cm", "LB1 reads SA Mn as CM")
h.assert_equal(line_break.raw_class(0x0E01), "Sa", "U+0E01 is SA")
h.assert_equal(line_break.resolved_class(0x0E01), "Al", "LB1 reads SA Lo as AL")

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
        error("line-break conformance: unparseable token '" .. tok .. "'")
      end
      cps[#cps + 1] = cp
    end
  end
  return cps, expected
end

-- Hand-written vectors cannot establish a segmentation algorithm: its rules
-- read context on both sides of a boundary and the answer depends on state
-- carried from earlier in the sequence, so a wrong rule survives any vector a
-- person would pick. Agreeing with all of them is also the evidence the two
-- departures declared at line_break.lua's head needed -- nil-yielding table
-- reads in place of the Lean's positional lits[i]!, and dropping its write-only
-- spSinceNoSp snapshot field.
local f = assert(io.open("testdata/LineBreakTest.txt", "r"))
local rows = 0
local lineno = 0
for line in f:lines() do
  lineno = lineno + 1
  local trimmed = line:gsub("^%s+", ""):gsub("%s+$", "")
  if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" then
    local cps, expected = parse_line(line)
    if #expected ~= #cps + 1 then
      error(
        "line-break conformance line "
          .. lineno
          .. ": expected "
          .. (#cps + 1)
          .. " boundary markers, got "
          .. #expected
      )
    end
    local actual = line_break.line_breaks(cps)
    h.assert_equal(actual, expected, "LineBreakTest line " .. lineno)
    rows = rows + 1
  end
end
f:close()

-- The vendored copy must carry every row the canonical file did. Without this
-- a row lost between the two would shrink the denominator instead of failing.
h.assert_equal(rows, tables.PUBLISHED_ROW_COUNT,
  "the vendored corpus carries every published row")

print("line_break: validated " .. rows .. " LineBreakTest rows")
