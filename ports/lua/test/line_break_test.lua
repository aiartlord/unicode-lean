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

-- // shared vector fixture // -------------------------------------------------

-- One case per UAX #14 rule, the same bytes in every port, so no port can carry
-- a weaker set of rule checks than another. The published corpus below is the
-- authority; these name which rule each boundary exercises.
local fixture = h.segmentation_fixture("line_break_vectors.json")
h.assert_equal(fixture.schema, 1, "line-break fixture schema")
h.assert_equal(fixture.algorithm, "uax14-line-break",
  "line-break fixture algorithm")
if #fixture.cases == 0 then
  error("line-break vectors: fixture carries no cases")
end
for _, case in ipairs(fixture.cases) do
  local actual = line_break.line_breaks(case.input)
  h.assert_equal(actual, case.breaks, case.rule .. ": " .. case.name)
end
print("line_break: replayed " .. #fixture.cases .. " shared vector cases")

-- The vendored corpus and the vendored vectors must agree on how many rows the
-- published file carries, so the two gates cannot drift apart.
h.assert_equal(tables.PUBLISHED_ROW_COUNT, fixture.published_row_count,
  "table row count agrees with the shared fixture")

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

-- LB18 breaks after a space, so the space stays with the word before it. The
-- run split is a shape the boundary masks above do not state.
local spaced = line_break.line_runs({ 0x61, 0x20, 0x62 })
h.assert_equal(#spaced, 2, "a space opens the next run")
h.assert_equal(spaced[1], { 0x61, 0x20 }, "the space stays with the word before it")
h.assert_equal(spaced[2], { 0x62 }, "the next run starts after the space")

-- LB25: "1,000" is one run across its separator.
h.assert_equal(
  #line_break.line_runs({ 0x31, 0x2C, 0x30, 0x30, 0x30 }),
  1,
  "a numeric chain is one run"
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
