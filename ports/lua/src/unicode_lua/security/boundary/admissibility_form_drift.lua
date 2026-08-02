-- AdmissibilityFormDrift — cross-layer identifier-admissibility x form drift
-- (boundary-layer detector).
--
-- Byte-faithful transcription of the verified Rust reference implementation,
-- itself a transcription of `Unicode/Security/Boundary/AdmissibilityFormDrift.lean`.
--
-- Fires on inputs whose UTS #39 whole-string `is_allowed_identifier` verdict
-- differs between the input and its NFKC form. This is the string-level
-- complement of IdentifierFormDrift (which scans `Identifier_Status` against the
-- per-codepoint NFKD head): here the whole-string admissibility predicate is
-- evaluated twice — once on the input, once on `to_nfkc(input)`. The two are not
-- redundant. In particular, a sequence of decomposed Hangul jamos passes the
-- per-codepoint scan cleanly (each jamo has identity NFKD and Restricted status
-- on both sides) but fires here: the jamo sequence is rejected by
-- `is_allowed_identifier`, while its NFKC composition into a precomposed Hangul
-- syllable is accepted.
--
-- It reuses the port's own UTS #39 admissibility predicate
-- (`ucd.is_allowed_identifier` = UAX #31 default identifier ∧ every codepoint
-- Allowed) and NFKC pipeline (`ucd.to_nfkc`), never a host normalization or
-- identifier library.
--
-- Sub-threat (direction-agnostic):
--   AdmissibilityFormDrift — `is_allowed_identifier(input) !=
--   is_allowed_identifier(to_nfkc(input))`. The pair of booleans is carried so
--   the verdict records which direction the drift goes; no position is reported
--   because the predicate is whole-string.

local ucd = require("unicode_lua.security.identity.ucd")

local unpack = table.unpack or unpack

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §2 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The AdmissibilityFormDrift detection function. Returns a verdict table
-- mirroring the Rust `Verdict`: `input`, `classify` (`{ kind, sub, positions,
-- decoded }`), `input_admissible`, `nfkc_admissible`.
function M.detect(input)
  local nfkc = ucd.to_nfkc(input)
  local in_ok = ucd.is_allowed_identifier(input)
  local nfkc_ok = ucd.is_allowed_identifier(nfkc)

  local classify
  if in_ok == nfkc_ok then
    classify = { kind = "Clear", sub = nil, positions = {}, decoded = {} }
  else
    classify = {
      kind = "Hazard",
      sub = {
        tag = "AdmissibilityFormDrift",
        input_admissible = in_ok,
        nfkc_admissible = nfkc_ok,
      },
      positions = {},
      decoded = {},
    }
  end

  local input_copy = {}
  if #input > 0 then
    input_copy = { unpack(input) }
  end

  return {
    input = input_copy,
    classify = classify,
    input_admissible = in_ok,
    nfkc_admissible = nfkc_ok,
  }
end

-- True iff the verdict's classification is Clear.
function M.is_clear(verdict)
  return verdict.classify.kind == "Clear"
end

-- Human-facing tag for a verdict's classification, or nil when clear. Exhaustive
-- over the sole sub-threat; an unknown tag is a construction bug and raises.
function M.classification_tag(verdict)
  local sub = verdict.classify.sub
  if sub == nil then
    return nil
  end
  local tag = sub.tag
  if tag == "AdmissibilityFormDrift" then
    return "AdmissibilityFormDrift"
  else
    error("classification_tag: unknown AdmissibilityFormDrift sub-threat " .. tostring(tag))
  end
end

-- Implicated positions (always empty — the predicate is whole-string).
function M.classification_positions(verdict)
  return verdict.classify.positions
end

return M
