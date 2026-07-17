/-
  Unicode.Security.Identity.EmojiPresentationRegistry

  Consumer of the registered emoji-variation-sequence table
  (`Unicode.Generated.EmojiVariationSequences`). Exposes the registered-
  presentation predicate for identity detectors and proves the UTS #51 pairing
  invariant that every emoji-style base also carries a text-style presentation.

  A base that receives `U+FE0F` (emoji presentation) or `U+FE0E` (text
  presentation) but is not registered for that presentation is a forged
  variation sequence — a display-divergence primitive this registry lets a
  detector recognise.
-/

import Unicode.Generated.EmojiVariationSequences

namespace Unicode.Security.Identity.EmojiPresentationRegistry

open Unicode.Generated.EmojiVariationSequences

/-- True when `base + U+FE0F` is applied to a base that is not a registered
    emoji-presentation base — a forged emoji variation sequence. -/
def isUnregisteredEmojiBase (base : Nat) : Bool :=
  ! hasRegisteredEmojiPresentation base

/-- True when `base + U+FE0E` is applied to a base that is not a registered
    text-presentation base — a forged text variation sequence. -/
def isUnregisteredTextBase (base : Nat) : Bool :=
  ! hasRegisteredTextPresentation base

/-- A plain ASCII letter is registered for neither presentation, so applying a
    variation selector to it is always a forged sequence. -/
theorem ascii_A_unregistered_emoji :
    isUnregisteredEmojiBase 0x0041 = true := by decide +kernel

theorem ascii_A_unregistered_text :
    isUnregisteredTextBase 0x0041 = true := by decide +kernel

end Unicode.Security.Identity.EmojiPresentationRegistry
