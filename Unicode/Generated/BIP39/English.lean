/-
  Unicode.Generated.BIP39.English

  BIP-39 English wordlist (2,048 words) parsed from
  `Unicode/Ucd/BIP39/english.txt`.  The file is byte-identical to
  the publication at
  `https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt`
  and pinned in `Unicode/Ucd/BIP39/SHA256SUMS`.

  Word indices `0..2047` match the canonical BIP-39 mapping used
  by every wallet implementation: a 132-bit checksummed entropy
  blob is encoded as eleven-bit groups, each looked up in this
  array.
-/

namespace Unicode.Generated.BIP39.English

/-- Raw wordlist text embedded at compile time. -/
def rawText : String := include_str "../../Ucd/BIP39/english.txt"

/-- The 2,048 words in canonical BIP-39 order. -/
def wordlist : Array String :=
  ((rawText.splitOn "\n").filter (fun s => ! s.isEmpty)).toArray

theorem wordlist_count : wordlist.size = 2048 := by native_decide

theorem first_word : wordlist[0]! = "abandon" := by native_decide

theorem last_word : wordlist[2047]! = "zoo" := by native_decide

end Unicode.Generated.BIP39.English
