/-
  Unicode.Conformance.EmojiTest

  UTS #51 emoji-property conformance. Each theorem checks an `Unicode.Emoji`
  classifier against the property value Unicode's emoji data files assign to a
  representative codepoint.
-/

import Unicode.Emoji

namespace Unicode.Conformance.EmojiTest

open Unicode.Emoji

-- The emoji property tables are scanned past the default reducer budget.
set_option maxRecDepth 1000000

/-- GRINNING FACE (U+1F600) has the Emoji property. -/
theorem vector_grinning_is_emoji : isEmoji 0x1F600 = true := by decide

/-- GRINNING FACE defaults to emoji presentation (Emoji_Presentation). -/
theorem vector_grinning_is_presentation : isEmojiPresentation 0x1F600 = true := by decide

/-- ASCII 'A' is not an emoji. -/
theorem vector_ascii_not_emoji : isEmoji 0x41 = false := by decide

/-- The keycap digit base '#' (U+0023) has the Emoji property but not default emoji
    presentation (it needs an explicit VS16 to display as emoji). -/
theorem vector_hash_not_presentation : isEmojiPresentation 0x0023 = false := by decide

end Unicode.Conformance.EmojiTest
