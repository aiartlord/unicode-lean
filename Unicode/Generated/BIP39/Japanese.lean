/-
  Unicode.Generated.BIP39.Japanese

  BIP-39 Japanese wordlist (2,048 words) parsed from
  `Unicode/Ucd/BIP39/japanese.txt`.  The file is byte-identical
  to the publication at
  `https://github.com/bitcoin/bips/blob/master/bip-0039/japanese.txt`
  and pinned in `Unicode/Ucd/BIP39/SHA256SUMS`.

  Per BIP-39 §"Wordlist", Japanese mnemonics use the ideographic
  space `U+3000` rather than ASCII `U+0020` as the word separator
  when reconstructed; this module exposes the words themselves
  separated by newlines and leaves separator-choice policy to the
  caller.
-/

namespace Unicode.Generated.BIP39.Japanese

/-- Raw wordlist text embedded at compile time. -/
def rawText : String := include_str "../../Ucd/BIP39/japanese.txt"

/-- The 2,048 words in canonical BIP-39 order. -/
def wordlist : Array String :=
  ((rawText.splitOn "\n").filter (fun s => ! s.isEmpty)).toArray

theorem wordlist_count : wordlist.size = 2048 := by native_decide

end Unicode.Generated.BIP39.Japanese
