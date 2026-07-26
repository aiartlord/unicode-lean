/-
  Unicode.Generated.UnihanVariantTypes

  Row shape for UAX #38 Unihan variant relationships: one source
  codepoint, one variant property, and the cited target codepoints.
  `UnihanVariants` populates these rows from `Unihan_Variants.txt`.
-/

namespace Unicode.Generated.UnihanVariants

inductive VariantProperty where
  | SimplifiedVariant
  | TraditionalVariant
  | SemanticVariant
  | SpecializedSemanticVariant
  | SpoofingVariant
  | ZVariant
  deriving DecidableEq, BEq, Repr, Inhabited

structure Row where
  source : Nat
  property : VariantProperty
  targets : List Nat
  deriving BEq, Repr, Inhabited

end Unicode.Generated.UnihanVariants
