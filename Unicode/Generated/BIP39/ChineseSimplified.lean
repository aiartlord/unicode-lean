/-
  Unicode.Generated.BIP39.ChineseSimplified

  BIP-39 Simplified-Chinese wordlist (2,048 words) parsed from
  `Unicode/Ucd/BIP39/chinese_simplified.txt`.  The file is
  byte-identical to the publication at
  `https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_simplified.txt`
  and pinned in `Unicode/Ucd/BIP39/SHA256SUMS`.
-/

namespace Unicode.Generated.BIP39.ChineseSimplified

/-- Raw wordlist text embedded at compile time. -/
def rawText : String := include_str "../../Ucd/BIP39/chinese_simplified.txt"

/-- The 2,048 words in canonical BIP-39 order. -/
def wordlist : Array String :=
  ((rawText.splitOn "\n").filter (fun s => ! s.isEmpty)).toArray

theorem wordlist_count : wordlist.size = 2048 := by native_decide

end Unicode.Generated.BIP39.ChineseSimplified
