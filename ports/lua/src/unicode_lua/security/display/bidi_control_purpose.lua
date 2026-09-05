-- BidiControlPurpose — which bidi format controls serve a purpose, and which do
-- not.
--
-- Direct port of `Unicode/Security/Display/BidiControlPurpose.lean`. The nine
-- UAX #9 format controls exist to manage right-to-left text: a span is doing
-- that job when the text it encloses is right-to-left, or when it forces
-- left-to-right text inside a right-to-left context. A span enclosing no strong
-- right-to-left character in a left-to-right context manages nothing (`LRI user
-- PDI` around Latin text, `LRO return PDF` around a keyword), and an unbalanced
-- control never manages anything. Every Trojan Source payload is a control of
-- that kind; a balanced embedding around an Arabic string literal is the
-- opposite case and renders the literal as written.
--
-- This is not source-region filtering: the question is asked of every control
-- wherever it sits, and it is decided from the codepoints the span encloses,
-- never from where a tokenizer would place it.
--
-- Rule, as the Lean `walk` states it:
--
--   - An opener pushes a span: its position, whether it is an isolate (closed
--     by PDI) or an embedding/override (closed by PDF), and whether it is
--     right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
--     LRI).
--   - Every other codepoint is recorded against the innermost open span only:
--     strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
--     syntax. A nested span manages its own content.
--   - PDF closes the top span when it is an embedding; against an isolate on
--     top, or an empty stack, it is an orphan. PDI closes down to the innermost
--     isolate, implicitly terminating the embeddings above it, which are thereby
--     unbalanced; with no isolate open it is an orphan.
--   - A closed span is purposeful iff its direct content is exactly its own
--     direction and carries no code syntax; a left-to-right span additionally
--     needs right-to-left context (an enclosing right-to-left span, or a
--     paragraph whose first strong character is right-to-left).
--   - Reported: every orphan, every opener still open at the end, every
--     embedding a PDI terminated implicitly, and both ends of every closed span
--     that was not purposeful.
--
-- The strong-direction predicates are the port's own `ucd.is_strong_rtl` /
-- `ucd.is_strong_ltr` over the pinned bidi table. Positions are 0-based to
-- mirror the reference.

local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

-- RLE, RLO, RLI, or FSI (whose direction resolves from its content).
function M.opens_rtl_kind(cp)
  return cp == 0x202B or cp == 0x202E or cp == 0x2067 or cp == 0x2068
end

-- LRE, LRO, LRI.
function M.opens_ltr_kind(cp)
  return cp == 0x202A or cp == 0x202D or cp == 0x2066
end

-- LRI, RLI, FSI.
function M.opens_isolate_kind(cp)
  return cp == 0x2066 or cp == 0x2067 or cp == 0x2068
end

-- The ASCII codepoints a Trojan Source payload moves: quotes, brackets, comment
-- markers, statement separators, operators. Prose punctuation, space and digits
-- are not in the set.
local CODE_SYNTAX = {
  [0x22] = true, [0x27] = true, [0x60] = true, [0x28] = true, [0x29] = true,
  [0x5B] = true, [0x5D] = true, [0x7B] = true, [0x7D] = true, [0x2F] = true,
  [0x5C] = true, [0x2A] = true, [0x23] = true, [0x3B] = true, [0x3C] = true,
  [0x3E] = true, [0x3D] = true, [0x2B] = true, [0x7C] = true, [0x26] = true,
  [0x25] = true, [0x24] = true, [0x40] = true, [0x5E] = true, [0x7E] = true,
}

function M.is_code_syntax(cp)
  return CODE_SYNTAX[cp] == true
end

-- UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
-- character is right-to-left.
function M.paragraph_is_rtl(input)
  for i = 1, #input do
    if ucd.is_strong_rtl(input[i]) then
      return true
    end
    if ucd.is_strong_ltr(input[i]) then
      return false
    end
  end
  return false
end

-- A closed span is purposeful iff its direct content is exactly its own
-- direction and carries no code syntax; a left-to-right span additionally needs
-- right-to-left context.
local function span_purposeful(span, enclosing, paragraph_rtl)
  if span.rtl_kind then
    return span.saw_rtl and not span.saw_ltr and not span.saw_syntax
  end
  local in_rtl_context = paragraph_rtl
  for _, e in ipairs(enclosing) do
    if e.rtl_kind then
      in_rtl_context = true
    end
  end
  return in_rtl_context and span.saw_ltr and not span.saw_rtl and not span.saw_syntax
end

-- 0-based positions of the purposeless bidi format controls in the input, in
-- input order. Empty iff every control is balanced and manages right-to-left
-- text.
function M.purposeless_control_positions(input)
  local paragraph_rtl = M.paragraph_is_rtl(input)
  -- The stack's last element is the innermost open span.
  local stack = {}
  local reported = {}

  for i = 1, #input do
    local idx = i - 1
    local cp = input[i]
    if M.opens_rtl_kind(cp) or M.opens_ltr_kind(cp) then
      stack[#stack + 1] = {
        pos = idx,
        isolate = M.opens_isolate_kind(cp),
        rtl_kind = M.opens_rtl_kind(cp),
        saw_rtl = false,
        saw_ltr = false,
        saw_syntax = false,
      }
    elseif cp == 0x202C then
      -- PDF closes the top embedding; an isolate on top or an empty stack
      -- makes it an orphan.
      local top = stack[#stack]
      if top == nil or top.isolate then
        reported[#reported + 1] = idx
      else
        stack[#stack] = nil
        if not span_purposeful(top, stack, paragraph_rtl) then
          reported[#reported + 1] = top.pos
          reported[#reported + 1] = idx
        end
      end
    elseif cp == 0x2069 then
      -- PDI closes down to the innermost isolate; the embeddings above it are
      -- terminated implicitly and so unbalanced. No isolate open: orphan.
      local iso_index = nil
      for k = #stack, 1, -1 do
        if stack[k].isolate then
          iso_index = k
          break
        end
      end
      if iso_index == nil then
        reported[#reported + 1] = idx
      else
        for k = iso_index + 1, #stack do
          reported[#reported + 1] = stack[k].pos
        end
        local closed = stack[iso_index]
        for k = #stack, iso_index, -1 do
          stack[k] = nil
        end
        if not span_purposeful(closed, stack, paragraph_rtl) then
          reported[#reported + 1] = closed.pos
          reported[#reported + 1] = idx
        end
      end
    elseif #stack > 0 then
      local top = stack[#stack]
      top.saw_rtl = top.saw_rtl or ucd.is_strong_rtl(cp)
      top.saw_ltr = top.saw_ltr or ucd.is_strong_ltr(cp)
      top.saw_syntax = top.saw_syntax or M.is_code_syntax(cp)
    end
  end

  -- Every opener still open at the end is unbalanced.
  for _, open in ipairs(stack) do
    reported[#reported + 1] = open.pos
  end

  local seen = {}
  local unique = {}
  for _, pos in ipairs(reported) do
    if not seen[pos] then
      seen[pos] = true
      unique[#unique + 1] = pos
    end
  end
  table.sort(unique)
  return unique
end

-- True iff the input carries at least one purposeless bidi format control.
function M.has_purposeless_control(input)
  return #M.purposeless_control_positions(input) > 0
end

-- 0-based position and codepoint of the first purposeless control, or nil, nil
-- when every control is purposeful.
function M.first_purposeless_control(input)
  local positions = M.purposeless_control_positions(input)
  if #positions == 0 then
    return nil, nil
  end
  return positions[1], input[positions[1] + 1]
end

return M
