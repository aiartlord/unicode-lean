/-
  Unicode.Generated.BIP39.Italian

  BIP-39 Italian wordlist (2,048 words) parsed from
  `Unicode/Ucd/BIP39/italian.txt`.  The file is byte-identical to
  the publication at
  `https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt`
  and pinned in `Unicode/Ucd/BIP39/SHA256SUMS`.
-/

namespace Unicode.Generated.BIP39.Italian

/-- Raw wordlist text embedded at compile time. -/
def rawText : String := include_str "../../Ucd/BIP39/italian.txt"

/-- The 2,048 words in canonical BIP-39 order. -/
def wordlist : Array String :=
  ((rawText.splitOn "\n").filter (fun s => ! s.isEmpty)).toArray

theorem wordlist_count : wordlist.size = 2048 := by native_decide

end Unicode.Generated.BIP39.Italian
