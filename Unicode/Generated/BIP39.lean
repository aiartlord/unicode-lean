/-
  Unicode.Generated.BIP39

  Aggregate over the 10 BIP-39 wordlists.  Each per-language
  module under `Unicode/Generated/BIP39/<Lang>.lean` parses its
  byte-identical upstream `.txt` file once at module load and
  exposes `wordlist : Array String` with 2,048 entries.

  This module wraps them in a `Language` enum + `wordlist`
  dispatch so callers that work with mnemonics across languages
  can switch on a single tag rather than importing ten modules.
-/

import Unicode.Generated.BIP39.English
import Unicode.Generated.BIP39.Japanese
import Unicode.Generated.BIP39.Korean
import Unicode.Generated.BIP39.Spanish
import Unicode.Generated.BIP39.ChineseSimplified
import Unicode.Generated.BIP39.ChineseTraditional
import Unicode.Generated.BIP39.French
import Unicode.Generated.BIP39.Italian
import Unicode.Generated.BIP39.Czech
import Unicode.Generated.BIP39.Portuguese

namespace Unicode.Generated.BIP39

/-- The ten BIP-39-defined languages.  Constructor names match
    the `Unicode/Generated/BIP39/<Name>.lean` module suffixes. -/
inductive Language where
  | english
  | japanese
  | korean
  | spanish
  | chineseSimplified
  | chineseTraditional
  | french
  | italian
  | czech
  | portuguese
  deriving DecidableEq, Repr, Inhabited

/-- Get the canonical 2,048-word array for `lang`. -/
def wordlist : Language → Array String
  | .english             => English.wordlist
  | .japanese            => Japanese.wordlist
  | .korean              => Korean.wordlist
  | .spanish             => Spanish.wordlist
  | .chineseSimplified   => ChineseSimplified.wordlist
  | .chineseTraditional  => ChineseTraditional.wordlist
  | .french              => French.wordlist
  | .italian             => Italian.wordlist
  | .czech               => Czech.wordlist
  | .portuguese          => Portuguese.wordlist

/-- All ten languages, in declaration order. -/
def allLanguages : Array Language :=
  #[.english, .japanese, .korean, .spanish,
    .chineseSimplified, .chineseTraditional,
    .french, .italian, .czech, .portuguese]

/-- Every language's wordlist has exactly 2,048 entries. -/
theorem every_wordlist_2048 :
    allLanguages.all (fun lang => (wordlist lang).size = 2048) = true := by
  native_decide

end Unicode.Generated.BIP39
