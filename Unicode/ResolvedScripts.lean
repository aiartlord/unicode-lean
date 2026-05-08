/-
  Unicode.ResolvedScripts

  Per-codepoint resolved Script_Extensions per UAX #44 § 5.10:

      scx(cp)  =  if cp is listed in `ScriptExtensions.txt` then
                    that explicit ISO-15924 abbreviation list
                  else
                    `[Script(cp)]`

  Two enums collide here. `Unicode.Generated.Scripts.Script` carries
  the full ISO-15924 *name* set (200+ values, parsed from
  `Scripts.txt`). `Unicode.Generated.ScriptExtensions.ScriptAbbrev`
  carries the 4-letter *abbreviations* (96 values, parsed from
  `ScriptExtensions.txt`). The abbrev set is smaller because
  `ScriptExtensions.txt` only lists codepoints whose `scx` is not
  exactly the singleton `[Script(cp)]`.

  The bridge `scriptToAbbrev` maps Script → Option ScriptAbbrev:
  most Recommended scripts have a corresponding abbrev; rare or
  esoteric scripts that never appear in `scx` data return `none`
  and contribute the empty set to the resolved-scripts of any
  codepoint defaulted to them. Per UTS #39 § 5.1 the practical
  consequence is that a codepoint of an unrecognised script causes
  the string to fail Single-Script (the intersection is empty);
  this matches the spec's intent — esoteric scripts are not
  Recommended, so identifiers using them are Unrestricted.
-/

import Unicode.Generated.Scripts
import Unicode.Generated.ScriptExtensions

namespace Unicode.ResolvedScripts

open Unicode.Generated.Scripts (Script lookupScript)
open Unicode.Generated.ScriptExtensions (ScriptAbbrev scriptExtensionRanges)

/-- Map a `Script` enum value to its 4-letter ISO-15924 abbreviation,
    when the abbreviation is in the `ScriptAbbrev` enum. Scripts
    without an entry (Common, Inherited, Unknown, and the rare
    archaic / regional scripts that never appear in
    `ScriptExtensions.txt`) return `none`. -/
def scriptToAbbrev : Script → Option ScriptAbbrev
  | .Adlam                  => some .Adlm
  | .Caucasian_Albanian     => some .Aghb
  | .Arabic                 => some .Arab
  | .Armenian               => some .Armn
  | .Avestan                => some .Avst
  | .Bengali                => some .Beng
  | .Bopomofo               => some .Bopo
  | .Buginese               => some .Bugi
  | .Buhid                  => some .Buhd
  | .Chakma                 => some .Cakm
  | .Carian                 => some .Cari
  | .Cherokee               => some .Cher
  | .Coptic                 => some .Copt
  | .Cypro_Minoan           => some .Cpmn
  | .Cypriot                => some .Cprt
  | .Cyrillic               => some .Cyrl
  | .Devanagari             => some .Deva
  | .Dogra                  => some .Dogr
  | .Duployan               => some .Dupl
  | .Elbasan                => some .Elba
  | .Ethiopic               => some .Ethi
  | .Garay                  => some .Gara
  | .Georgian               => some .Geor
  | .Glagolitic             => some .Glag
  | .Gunjala_Gondi          => some .Gong
  | .Masaram_Gondi          => some .Gonm
  | .Gothic                 => some .Goth
  | .Grantha                => some .Gran
  | .Greek                  => some .Grek
  | .Gujarati               => some .Gujr
  | .Gurung_Khema           => some .Gukh
  | .Gurmukhi               => some .Guru
  | .Hangul                 => some .Hang
  | .Han                    => some .Hani
  | .Hanunoo                => some .Hano
  | .Hebrew                 => some .Hebr
  | .Hiragana               => some .Hira
  | .Old_Hungarian          => some .Hung
  | .Javanese               => some .Java
  | .Kayah_Li               => some .Kali
  | .Katakana               => some .Kana
  | .Khojki                 => some .Khoj
  | .Kannada                => some .Knda
  | .Kaithi                 => some .Kthi
  | .Latin                  => some .Latn
  | .Limbu                  => some .Limb
  | .Linear_A               => some .Lina
  | .Linear_B               => some .Linb
  | .Lisu                   => some .Lisu
  | .Lycian                 => some .Lyci
  | .Lydian                 => some .Lydi
  | .Mahajani               => some .Mahj
  | .Mandaic                => some .Mand
  | .Manichaean             => some .Mani
  | .Meroitic_Hieroglyphs   => some .Mero
  | .Malayalam              => some .Mlym
  | .Modi                   => some .Modi
  | .Mongolian              => some .Mong
  | .Multani                => some .Mult
  | .Myanmar                => some .Mymr
  | .Nandinagari            => some .Nand
  | .Newa                   => some .Newa
  | .Nko                    => some .Nkoo
  | .Ol_Onal                => some .Onao
  | .Old_Turkic             => some .Orkh
  | .Oriya                  => some .Orya
  | .Osage                  => some .Osge
  | .Old_Uyghur             => some .Ougr
  | .Old_Permic             => some .Perm
  | .Phags_Pa               => some .Phag
  | .Psalter_Pahlavi        => some .Phlp
  | .Hanifi_Rohingya        => some .Rohg
  | .Runic                  => some .Runr
  | .Samaritan              => some .Samr
  | .Shavian                => some .Shaw
  | .Sharada                => some .Shrd
  | .Khudawadi              => some .Sind
  | .Sinhala                => some .Sinh
  | .Sogdian                => some .Sogd
  | .Sunuwar                => some .Sunu
  | .Syloti_Nagri           => some .Sylo
  | .Syriac                 => some .Syrc
  | .Tagbanwa               => some .Tagb
  | .Takri                  => some .Takr
  | .Tai_Le                 => some .Tale
  | .Tamil                  => some .Taml
  | .Tangut                 => some .Tang
  | .Telugu                 => some .Telu
  | .Tifinagh               => some .Tfng
  | .Tagalog                => some .Tglg
  | .Thaana                 => some .Thaa
  | .Thai                   => some .Thai
  | .Tibetan                => some .Tibt
  | .Tirhuta                => some .Tirh
  | .Todhri                 => some .Todr
  | .Toto                   => some .Toto
  | .Tulu_Tigalari          => some .Tutg
  | .Yezidi                 => some .Yezi
  | .Yi                     => some .Yiii
  | unrecognisedScript      => Function.const Script none unrecognisedScript

/-- True iff the codepoint's Script is Common (Zyyy) per UAX #24.
    Common scripts (punctuation, digits, symbols) are ignored when
    computing the resolved-script intersection for restriction-level
    purposes. -/
def isCommonScript (cp : Nat) : Bool :=
  match lookupScript cp with
  | .Common => true
  | _       => false

/-- True iff the codepoint's Script is Inherited (Zinh).
    Inherited-script codepoints are combining marks that take their
    script from the preceding base, also ignored in resolution. -/
def isInheritedScript (cp : Nat) : Bool :=
  match lookupScript cp with
  | .Inherited => true
  | _          => false

/-- The resolved Script_Extensions of `cp`, returned as a list of
    abbreviations. If `cp` appears in `scriptExtensionRanges`, the
    explicit list is used; otherwise the singleton list of `cp`'s
    `Script` is used (or empty when the Script has no abbreviation
    in `ScriptAbbrev`). -/
def resolveScripts (cp : Nat) : Array ScriptAbbrev :=
  match scriptExtensionRanges.findSome? (fun ⟨lo, hi, abbrevs⟩ =>
          if lo ≤ cp ∧ cp ≤ hi then some abbrevs else none) with
  | some abbrevs => abbrevs
  | none =>
    match scriptToAbbrev (lookupScript cp) with
    | some s => #[s]
    | none   => #[]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SAMPLE LOOKUPS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII letter 'a' resolves to {Latn}. -/
theorem resolve_ascii_a :
    resolveScripts 0x0061 = #[.Latn] := by native_decide

/-- ASCII digit '0' has Script = Common, which has no
    `ScriptAbbrev` entry, so it resolves to the empty set.
    UTS #39 treats Common-script codepoints as ignored in
    Single-Script intersection (they don't contribute and they
    don't fail). -/
theorem resolve_ascii_0 :
    resolveScripts 0x0030 = #[] := by native_decide

/-- Common-script detection: ASCII digit is Common. -/
theorem isCommon_ascii_0 : isCommonScript 0x0030 = true := by native_decide

/-- Cyrillic small letter а (U+0430) resolves to {Cyrl}. -/
theorem resolve_cyrillic_a :
    resolveScripts 0x0430 = #[.Cyrl] := by native_decide

/-- Greek small letter alpha resolves to {Grek}. -/
theorem resolve_greek_alpha :
    resolveScripts 0x03B1 = #[.Grek] := by native_decide

/-- Hebrew letter alef resolves to {Hebr}. -/
theorem resolve_hebrew_alef :
    resolveScripts 0x05D0 = #[.Hebr] := by native_decide

/-- A Han ideograph resolves to a non-empty SCX (typically several
    East-Asian scripts share a Han codepoint via Script_Extensions). -/
theorem resolve_han_yi_nonempty :
    (resolveScripts 0x4E00).size > 0 := by native_decide

end Unicode.ResolvedScripts
