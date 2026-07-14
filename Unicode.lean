/-
  Unicode

  Default root for the Unicode standard's executable algorithms and runtime API
  surface, pinned at UCD 17.0.0.

  This root intentionally excludes proof-heavy normalization/idempotence
  assurance modules and row-backed conformance fixtures. Build
  `UnicodeAssurance` or `UnicodeFullConformance` when those evidence suites are
  required.
-/

-- Normalization (UAX #15): executable algorithms.
import Unicode.Normalization.NFD
import Unicode.Normalization.NFC
import Unicode.Normalization.NFKC
import Unicode.Normalization.NFKD
import Unicode.Normalization.CompatDecompose
import Unicode.Normalization.Reorder

-- PRECIS (RFC 8264 / 8265): runtime preparation/profile APIs.
import Unicode.Precis.PreparationCore
import Unicode.Precis.IdentifierClass
import Unicode.Precis.OpaqueStringCore
import Unicode.Precis.BidiRule
import Unicode.Precis.Categories
import Unicode.Precis.WidthMapping
import Unicode.Precis.CaseMapping
import Unicode.Precis.ZsMapping

-- Bidirectional Algorithm (UAX #9).
import Unicode.Bidi.Algorithm

-- Confusables (UTS #39 section 4).
import Unicode.Confusables

-- Segmentation (UAX #29 / UAX #14): algorithms plus declarative spec bridges.
import Unicode.Segmentation.GraphemeBreak
import Unicode.Segmentation.GraphemeBreakSpec
import Unicode.Segmentation.WordBreak
import Unicode.Segmentation.WordBreakSpec
import Unicode.Segmentation.SentenceBreak
import Unicode.Segmentation.LineBreak
import Unicode.Segmentation.LineBreakSpec
import Unicode.Segmentation.PrefixScan

-- Refinement-typed wrappers and invariants.
import Unicode.Refined
import Unicode.Invariants

-- RFC 3629 strict UTF-8 codec and scalar-stream validation.
import Unicode.Codec.Strict
import Unicode.Codec.Utf8
import Unicode.Codec.ValidatedUtf8
import Unicode.Normalization.Utf8Bridge
import Unicode.Codec.Utf8Roundtrip
import Unicode.Codec.Utf32
import Unicode.Codec.Utf16
import Unicode.Codec.Bom
import Unicode.Codec.Noncharacters
import Unicode.Codec.OpaqueBlob
import Unicode.Codec.Printable
import Unicode.Codec.Identifier

-- Display, identifiers, script resolution, and spoofing-relevant properties.
import Unicode.Width
import Unicode.Emoji
import Unicode.StreamSafe
import Unicode.ResolvedScripts
import Unicode.Restriction
import Unicode.TrojanSource
import Unicode.Vertical
import Unicode.Unihan
import Unicode.PropertyNames
import Unicode.Casing
import Unicode.Identifier

-- IDNA / Punycode / UTS #46 algorithm surface.
import Unicode.Idna.Punycode
import Unicode.Idna.Disposition
import Unicode.Idna.Map
import Unicode.Idna.CheckJoiners
import Unicode.Idna.Process

-- UTS #10 UCA algorithm surface.
import Unicode.Uca.Lookup
import Unicode.Uca.SortKey

-- Programmatic UCD digest manifest.
import Unicode.UCD

-- Generated UCD-derived tables used by the algorithm surface.
import Unicode.Generated.CompatDecomp
import Unicode.Generated.DerivedCoreProperties
import Unicode.Generated.DerivedJoiningType
import Unicode.Generated.EastAsianWidth
import Unicode.Generated.IdentifierType
import Unicode.Generated.IdnaMapping
import Unicode.Generated.PropList
import Unicode.Generated.ScriptExtensions
import Unicode.Generated.Scripts
import Unicode.Generated.StandardizedVariants
import Unicode.Generated.EmojiVariationSequences
import Unicode.Generated.Allkeys
import Unicode.Generated.BIP39
import Unicode.Generated.KnownAttackTargets
import Unicode.Generated.WatermarkSchemes
import Unicode.Generated.GlitchTokens

-- Security detector API surface. The detector modules still mix executable
-- implementations with example/evidence theorems; see the audit note for the
-- remaining split that should be done next.
import Unicode.Security
import Unicode.Security.RunAll
import Unicode.Security.Level
import Unicode.Security.Policy

-- Small arithmetic/list support modules used by downstream proofs.
import Unicode.NatListBounds
