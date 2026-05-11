/-
  Unicode

  Root import for the Unicode standard's machine-checked specifications,
  pinned at UCD 17.0.0 and Lean 4.28.0.
-/

-- Normalization (UAX #15)
import Unicode.Normalization.QuickCheckSoundnessTheorem
import Unicode.Normalization.NFKC
import Unicode.Normalization.NFKD
import Unicode.Normalization.CompatDecompose

-- PRECIS (RFC 8264 / 8265)
import Unicode.Precis.Preparation
import Unicode.Precis.IdentifierClass
import Unicode.Precis.OpaqueString
import Unicode.Precis.BidiRule
import Unicode.Precis.Categories
import Unicode.Precis.WidthMapping
import Unicode.Precis.CaseMapping
import Unicode.Precis.ZsPreservation

-- Bidirectional Algorithm (UAX #9)
import Unicode.Bidi.Algorithm

-- Confusables (UTS #39 §4)
import Unicode.Confusables

-- UAX #15 conformance — official NormalizationTest.txt against
-- toNFC / toNFD / toNFKC / toNFKD across all six @Part sections
import Unicode.Conformance.NormalizationTest

-- UAX #9 conformance — official BidiCharacterTest.txt against
-- bidiParagraph / bidiParagraphAt
import Unicode.Conformance.BidiCharacterTest

-- UAX #9 conformance — official BidiTest.txt level + L1/L2 reorder
-- across all paragraph-level settings
import Unicode.Conformance.BidiTest

-- UAX #29 segmentation — default grapheme cluster, word, and
-- sentence break algorithms
import Unicode.Segmentation.GraphemeBreak
import Unicode.Segmentation.WordBreak
import Unicode.Segmentation.SentenceBreak

-- UAX #29 conformance — official GraphemeBreakTest.txt,
-- WordBreakTest.txt, and SentenceBreakTest.txt
import Unicode.Conformance.GraphemeBreakTest
import Unicode.Conformance.WordBreakTest
import Unicode.Conformance.SentenceBreakTest

-- UAX #14 line breaking + conformance against LineBreakTest.txt
import Unicode.Segmentation.LineBreak
import Unicode.Conformance.LineBreakTest

-- Case-fold commutation and round-trip
import Unicode.CaseFoldCommutation
import Unicode.CaseFoldRoundtrip

-- Refinement-typed wrappers and invariants
import Unicode.Refined
import Unicode.Invariants

-- RFC 3629 strict UTF-8 codec + dual-API reject reasons
import Unicode.Codec.Strict
import Unicode.Codec.Utf8
import Unicode.Codec.ValidatedUtf8

-- UTF-8 ↔ codepoint bridge for byte-level NFC
import Unicode.Normalization.Utf8Bridge

-- Closed-form per-codepoint encode/decode roundtrip theorem
import Unicode.Codec.Utf8Roundtrip

-- UTF-32 codec (BE + LE) with per-codepoint roundtrip
import Unicode.Codec.Utf32

-- UTF-16 codec (BE + LE) with surrogate-pair encoding
import Unicode.Codec.Utf16

-- Byte-Order-Mark detection across UTF-8 / UTF-16 BE+LE / UTF-32 BE+LE
import Unicode.Codec.Bom

-- Noncharacter detection (66 designated noncharacters)
import Unicode.Codec.Noncharacters

-- UAX #11 East Asian Width — display column width for terminals
-- and fixed-width layout (per-codepoint and string-level)
import Unicode.Width

-- UTS #51 Emoji — variation selectors, regional indicators, modifier
-- sequences, keycap sequences, tag sequences, ZWJ sequences,
-- and the RGI (Recommended for General Interchange) sequence set
import Unicode.Emoji

-- UTS #51 conformance — official `emoji-test.txt` against
-- `isRgiEmoji` for every fully-qualified row
import Unicode.Conformance.EmojiTest

-- UAX #15 § 13 Stream-Safe Text Format — caps combining-mark runs
-- at 30 to bound normalization buffers and prevent DoS via long
-- combining-mark sequences
import Unicode.StreamSafe

-- Per-codepoint resolved Script_Extensions (UAX #44 § 5.10) plus
-- the Script ↔ ScriptAbbrev bridge needed by UTS #39 restriction-
-- level computation
import Unicode.ResolvedScripts

-- UTS #39 § 5 Restriction Levels and Mixed-Number Detection
import Unicode.Restriction

-- Trojan Source defense (CVE-2021-42574 / 2021-42694) — bidi
-- format-control detection, balance check, and `safeForCodeContext`
-- combining the strict-bidi reject with a restriction-level threshold
import Unicode.TrojanSource

-- UAX #50 Vertical Text Layout — `Vo` property and per-codepoint
-- vertical glyph orientation (Upright / Rotated)
import Unicode.Vertical

-- UAX #38 Unihan Database — variant relationships (Simplified ↔
-- Traditional, semantic, spoofing, Z-axis) and numeric values
-- (canonical, accounting/banking, script-specific)
import Unicode.Unihan

-- UAX #44 §5.10 — property and property-value alias resolution
-- with strict and loose-match (LM3 / LM4) lookups
import Unicode.PropertyNames

-- UAX #21 / SpecialCasing — locale- and context-aware uppercase /
-- lowercase / titlecase mappings, including Turkish dotted/dotless I,
-- Lithuanian dot above, and Greek final sigma
import Unicode.Casing

-- RFC 3492 Punycode encoding (foundation for UTS #46 IDNA processing)
import Unicode.Idna.Punycode

-- UTS #46 IDNA Compatible Preprocessing — disposition lookup, mapping pass,
-- ToUnicode / ToASCII pipeline, CONTEXTJ joiners check
import Unicode.Idna.Disposition
import Unicode.Idna.Map
import Unicode.Idna.CheckJoiners
import Unicode.Idna.Process

-- DerivedJoiningType table — Joining_Type lookup for CONTEXTJ rules
import Unicode.Generated.DerivedJoiningType

-- UCD 16.0.0 StandardizedVariants.txt — 1,306 sanctioned variation
-- sequences (math, Mongolian, Egyptian, CJK Compat, etc.). Used by
-- the C2 covert-channel detector to bipartition VS occurrences into
-- registered vs. suspicious.
import Unicode.Generated.StandardizedVariants

-- UCD 16.0.0 emoji-variation-sequences.txt — 371 base codepoints
-- × 2 VS each (FE0E text, FE0F emoji). Used by the C2 detector
-- to recognise sanctioned emoji-presentation vs text-presentation
-- VS uses without approximating via the wider Emoji property bit.
import Unicode.Generated.EmojiVariationSequences

-- UCA 16.0.0 DUCET — parsed table of collation elements
import Unicode.Generated.Allkeys

-- UTS #10 UCA — DUCET lookup, sort-key construction, comparison
import Unicode.Uca.Lookup
import Unicode.Uca.SortKey

-- UCA conformance — official CollationTest_*_SHORT.txt against
-- sortKey under both NON_IGNORABLE and SHIFTED variable handling.
import Unicode.Conformance.CollationTest

-- UTS #46 conformance — official IdnaTestV2.txt against
-- toUnicode / toAscii / toAsciiTransitional (strict subset)
import Unicode.Conformance.IdnaTestV2

-- UAX #31 — default identifier (R1-D1) + UTS #39 allowed-status profile
import Unicode.Identifier

-- Programmatic UCD digest manifest — exposes the SHA-256 pins for
-- downstream tools that want Lean-level verification rather than
-- shelling out to `scripts/check-ucd-hashes.sh`.
import Unicode.UCD

-- Spec-core text-codec predicates and refinement types (RFC 8264 PRECIS
-- profiles + structural UTF-8 opaque blob). Strict-cohesion wrappers
-- (StrictBox + RejectReason + wire-format framing) are downstream.
import Unicode.Codec.OpaqueBlob
import Unicode.Codec.Printable
import Unicode.Codec.Identifier

-- Generated UCD-derived tables (UCD 17.0.0)
import Unicode.Generated.CompatDecomp
import Unicode.Generated.DerivedCoreProperties
import Unicode.Generated.EastAsianWidth
import Unicode.Generated.IdentifierType
import Unicode.Generated.IdnaMapping
import Unicode.Generated.PropList
import Unicode.Generated.ScriptExtensions
import Unicode.Generated.Scripts

-- Security Conformance Layer — adversarial-threat-model verdicts
-- sitting below the UAX/UTS algorithm-correctness proof base above.
-- 26 fixture families across 6 layers (Covert / Identity / Display /
-- Form / Boundary / Crypto). v1: foundation calculus + C2 pilot;
-- remaining family modules land incrementally.
import Unicode.Security

-- Security Conformance Layer — per-family fixture-conformance proofs
-- (parallel structure to Unicode.Conformance.* for the UAX/UTS base).
import Unicode.Conformance.Security.VariationSelectorPayloadTest
import Unicode.Conformance.Security.TagBlockPayloadTest
import Unicode.Conformance.Security.BidiControlBalanceTest
import Unicode.Conformance.Security.ZeroWidthPayloadTest
import Unicode.Conformance.Security.SurrogateReassemblyTest
import Unicode.Conformance.Security.HomoglyphConfusableTest
import Unicode.Conformance.Security.SourceDisplayDivergenceTest
import Unicode.Conformance.Security.MixedScriptAdmissibilityTest
import Unicode.Conformance.Security.EmojiZwjIntegrityTest
import Unicode.Conformance.Security.SkinToneVariationForgeryTest
import Unicode.Conformance.Security.FilenameDisguiseTest
import Unicode.Conformance.Security.RtlInjectionTest
import Unicode.Conformance.Security.RendererDivergenceTest
import Unicode.Conformance.Security.NormalizationBombTest
import Unicode.Conformance.Security.StreamSafeViolationTest
import Unicode.Conformance.Security.LocaleCaseInversionTest
import Unicode.Conformance.Security.CaseExpansionMismatchTest
import Unicode.Conformance.Security.WidthClassConfusionTest
import Unicode.Conformance.Security.NfcIdempotenceWitnessTest
import Unicode.Conformance.Security.IdentifierFormDriftTest
import Unicode.Conformance.Security.CovertDisplayCompoundTest
