/-
  Unicode.PropertyNames

  UAX #44 §5.10 — property and property-value alias resolution.
  Wraps the parsed `PropertyAliases.txt` and `PropertyValueAliases.txt`
  tables in a unified API so a regex / query layer can normalise
  user-supplied property and value names to canonical short forms
  before lookup.

  Two tiers:

    * Property name aliases — `Bidi_Class`, `bc`, additional
                              spellings → canonical `bc`.
    * Property value aliases — for an enumerated property like
                              `bc`, `Arabic_Letter`, `AL`,
                              additional spellings → canonical
                              `AL`.

  Loose-match semantics (UAX #44 LM3 / LM4: case-insensitive,
  underscore-insensitive, hyphen-insensitive, whitespace-stripped)
  are layered on top of strict match. Most callers want the loose
  match; strict is exposed for full-fidelity reproductions of
  the UCD spelling.
-/

import Unicode.Generated.PropertyAliases
import Unicode.Generated.PropertyValueAliases

namespace Unicode.PropertyNames

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 LOOSE MATCH NORMALISER  (UAX #44 § LM3 / LM4)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Normalise a property or value name per UAX #44 LM3:
    case-insensitive, drop ASCII whitespace, drop underscores,
    drop hyphens. Preserves the leading "is" prefix that some
    aliases carry. -/
def looseNormalize (s : String) : String :=
  let lowered := s.toLower
  let folded := lowered.foldl (fun acc c =>
    let n := c.toNat
    if n = 0x20 ∨ n = 0x09 ∨ n = 0x0A ∨ n = 0x0D
        ∨ n = 0x5F ∨ n = 0x2D then acc
    else acc.push c) ""
  folded

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 PROPERTY NAME LOOKUPS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Strict-match lookup of the canonical short property name. -/
def propertyShort? (alias : String) : Option String :=
  Unicode.Generated.PropertyAliases.shortNameOf? alias

/-- Strict-match lookup of the canonical long property name. -/
def propertyLong? (alias : String) : Option String :=
  Unicode.Generated.PropertyAliases.longNameOf? alias

/-- Loose-match lookup of the canonical short property name. -/
def propertyShortLoose? (alias : String) : Option String :=
  let target := looseNormalize alias
  Unicode.Generated.PropertyAliases.parsedRows.findSome? (fun r =>
    if looseNormalize r.short = target
        ∨ looseNormalize r.long = target
        ∨ r.others.any (fun a => looseNormalize a = target)
      then some r.short else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PROPERTY VALUE LOOKUPS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Strict-match lookup of a canonical short value name. -/
def valueShort? (property valueAlias : String) : Option String :=
  Unicode.Generated.PropertyValueAliases.shortValueOf? property valueAlias

/-- Strict-match lookup of a canonical long value name. -/
def valueLong? (property valueAlias : String) : Option String :=
  Unicode.Generated.PropertyValueAliases.longValueOf? property valueAlias

/-- Loose-match lookup of a canonical short value name. The
    `property` argument is matched strictly (it should already be
    canonical); the value alias is loose-matched. -/
def valueShortLoose? (property valueAlias : String) : Option String :=
  let target := looseNormalize valueAlias
  Unicode.Generated.PropertyValueAliases.parsedRows.findSome? (fun r =>
    if r.property ≠ property then none
    else if looseNormalize r.short = target
            ∨ looseNormalize r.long = target
            ∨ r.others.any (fun a => looseNormalize a = target)
      then some r.short else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "bc" is the short name of Bidi_Class. -/
theorem propertyShort_bc : propertyShort? "bc" = some "bc" := by native_decide

/-- "Bidi_Class" resolves to short name "bc". -/
theorem propertyShort_BidiClass : propertyShort? "Bidi_Class" = some "bc" := by
  native_decide

/-- Loose match: "bidiclass" (no underscore) → "bc". -/
theorem propertyShortLoose_BidiClass :
    propertyShortLoose? "bidiclass" = some "bc" := by native_decide

/-- Loose match: " Bidi-Class " (whitespace + hyphen) → "bc". -/
theorem propertyShortLoose_messy :
    propertyShortLoose? " Bidi-Class " = some "bc" := by native_decide

/-- "AL" is the short name of Bidi_Class=Arabic_Letter. -/
theorem valueShort_AL :
    valueShort? "bc" "AL" = some "AL" := by native_decide

/-- "Arabic_Letter" resolves to "AL". -/
theorem valueShort_ArabicLetter :
    valueShort? "bc" "Arabic_Letter" = some "AL" := by native_decide

/-- Loose match for value name. -/
theorem valueShortLoose_arabicletter :
    valueShortLoose? "bc" "arabicletter" = some "AL" := by native_decide

/-- An unknown alias returns `none`. -/
theorem propertyShort_unknown :
    propertyShort? "definitely-not-a-property" = none := by native_decide

end Unicode.PropertyNames
