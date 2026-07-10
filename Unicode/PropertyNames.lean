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

set_option maxRecDepth 1000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 LOOSE MATCH NORMALISER  (UAX #44 § LM3 / LM4)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Normalise a property or value name per UAX #44 LM3:
    case-insensitive, drop ASCII whitespace, drop underscores,
    drop hyphens. Preserves the leading "is" prefix that some
    aliases carry. -/
def looseNormalize (s : String) : List Char :=
  -- Over `String.toList` (kernel-reducible) rather than `String.toLower`/
  -- `String.foldl` (which traverse via the byte iterator and do not reduce
  -- under `decide`). Lowercase each char, drop ASCII whitespace / underscore
  -- / hyphen; the result is a `List Char` so loose comparisons reduce in the
  -- kernel. `toLower` leaves the stripped set unchanged, so checking the
  -- lowered code point is equivalent to checking the original.
  s.toList.filterMap (fun c =>
    let l := c.toLower
    let n := l.toNat
    if n = 0x20 ∨ n = 0x09 ∨ n = 0x0A ∨ n = 0x0D
        ∨ n = 0x5F ∨ n = 0x2D then none
    else some l)

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
  Unicode.Generated.PropertyAliases.parsedRowsList.findSome? (fun r =>
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
  Unicode.Generated.PropertyValueAliases.parsedRowsList.findSome? (fun r =>
    if r.property ≠ property then none
    else if looseNormalize r.short = target
            ∨ looseNormalize r.long = target
            ∨ r.others.any (fun a => looseNormalize a = target)
      then some r.short else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "bc" is the short name of Bidi_Class. -/
theorem propertyShort_bc : propertyShort? "bc" = some "bc" := by decide +kernel

/-- "Bidi_Class" resolves to short name "bc". -/
theorem propertyShort_BidiClass : propertyShort? "Bidi_Class" = some "bc" := by
  decide +kernel

/-- Loose match: "bidiclass" (no underscore) → "bc". -/
theorem propertyShortLoose_BidiClass :
    propertyShortLoose? "bidiclass" = some "bc" := by decide +kernel

/-- Loose match: " Bidi-Class " (whitespace + hyphen) → "bc". -/
theorem propertyShortLoose_messy :
    propertyShortLoose? " Bidi-Class " = some "bc" := by decide +kernel

/-- "AL" is the short name of Bidi_Class=Arabic_Letter. -/
theorem valueShort_AL :
    valueShort? "bc" "AL" = some "AL" := by decide +kernel

/-- "Arabic_Letter" resolves to "AL". -/
theorem valueShort_ArabicLetter :
    valueShort? "bc" "Arabic_Letter" = some "AL" := by decide +kernel

/-- Loose match for value name. -/
theorem valueShortLoose_arabicletter :
    valueShortLoose? "bc" "arabicletter" = some "AL" := by decide +kernel

/-- An unknown alias returns `none`. -/
theorem propertyShort_unknown :
    propertyShort? "definitely-not-a-property" = none := by decide +kernel

end Unicode.PropertyNames
