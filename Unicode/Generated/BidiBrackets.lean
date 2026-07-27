/-
  Unicode.Generated.BidiBrackets

  Literal Bidi paired-bracket entries from BidiBrackets.txt.
-/

namespace Unicode.Generated.BidiBrackets

set_option maxRecDepth 100000

inductive BidiBracketType where
  | Open
  | Close
  deriving DecidableEq, Repr, Inhabited

structure BidiBracketRow where
  codepoint : Nat
  pair : Nat
  bracketType : BidiBracketType
  deriving Repr, Inhabited, DecidableEq

def bidiBracketRows : List BidiBracketRow := [
  { codepoint := 0x0028, pair := 0x0029, bracketType := .Open },
  { codepoint := 0x0029, pair := 0x0028, bracketType := .Close },
  { codepoint := 0x005B, pair := 0x005D, bracketType := .Open },
  { codepoint := 0x005D, pair := 0x005B, bracketType := .Close },
  { codepoint := 0x007B, pair := 0x007D, bracketType := .Open },
  { codepoint := 0x007D, pair := 0x007B, bracketType := .Close },
  { codepoint := 0x0F3A, pair := 0x0F3B, bracketType := .Open },
  { codepoint := 0x0F3B, pair := 0x0F3A, bracketType := .Close },
  { codepoint := 0x0F3C, pair := 0x0F3D, bracketType := .Open },
  { codepoint := 0x0F3D, pair := 0x0F3C, bracketType := .Close },
  { codepoint := 0x169B, pair := 0x169C, bracketType := .Open },
  { codepoint := 0x169C, pair := 0x169B, bracketType := .Close },
  { codepoint := 0x2045, pair := 0x2046, bracketType := .Open },
  { codepoint := 0x2046, pair := 0x2045, bracketType := .Close },
  { codepoint := 0x207D, pair := 0x207E, bracketType := .Open },
  { codepoint := 0x207E, pair := 0x207D, bracketType := .Close },
  { codepoint := 0x208D, pair := 0x208E, bracketType := .Open },
  { codepoint := 0x208E, pair := 0x208D, bracketType := .Close },
  { codepoint := 0x2308, pair := 0x2309, bracketType := .Open },
  { codepoint := 0x2309, pair := 0x2308, bracketType := .Close },
  { codepoint := 0x230A, pair := 0x230B, bracketType := .Open },
  { codepoint := 0x230B, pair := 0x230A, bracketType := .Close },
  { codepoint := 0x2329, pair := 0x232A, bracketType := .Open },
  { codepoint := 0x232A, pair := 0x2329, bracketType := .Close },
  { codepoint := 0x2768, pair := 0x2769, bracketType := .Open },
  { codepoint := 0x2769, pair := 0x2768, bracketType := .Close },
  { codepoint := 0x276A, pair := 0x276B, bracketType := .Open },
  { codepoint := 0x276B, pair := 0x276A, bracketType := .Close },
  { codepoint := 0x276C, pair := 0x276D, bracketType := .Open },
  { codepoint := 0x276D, pair := 0x276C, bracketType := .Close },
  { codepoint := 0x276E, pair := 0x276F, bracketType := .Open },
  { codepoint := 0x276F, pair := 0x276E, bracketType := .Close },
  { codepoint := 0x2770, pair := 0x2771, bracketType := .Open },
  { codepoint := 0x2771, pair := 0x2770, bracketType := .Close },
  { codepoint := 0x2772, pair := 0x2773, bracketType := .Open },
  { codepoint := 0x2773, pair := 0x2772, bracketType := .Close },
  { codepoint := 0x2774, pair := 0x2775, bracketType := .Open },
  { codepoint := 0x2775, pair := 0x2774, bracketType := .Close },
  { codepoint := 0x27C5, pair := 0x27C6, bracketType := .Open },
  { codepoint := 0x27C6, pair := 0x27C5, bracketType := .Close },
  { codepoint := 0x27E6, pair := 0x27E7, bracketType := .Open },
  { codepoint := 0x27E7, pair := 0x27E6, bracketType := .Close },
  { codepoint := 0x27E8, pair := 0x27E9, bracketType := .Open },
  { codepoint := 0x27E9, pair := 0x27E8, bracketType := .Close },
  { codepoint := 0x27EA, pair := 0x27EB, bracketType := .Open },
  { codepoint := 0x27EB, pair := 0x27EA, bracketType := .Close },
  { codepoint := 0x27EC, pair := 0x27ED, bracketType := .Open },
  { codepoint := 0x27ED, pair := 0x27EC, bracketType := .Close },
  { codepoint := 0x27EE, pair := 0x27EF, bracketType := .Open },
  { codepoint := 0x27EF, pair := 0x27EE, bracketType := .Close },
  { codepoint := 0x2983, pair := 0x2984, bracketType := .Open },
  { codepoint := 0x2984, pair := 0x2983, bracketType := .Close },
  { codepoint := 0x2985, pair := 0x2986, bracketType := .Open },
  { codepoint := 0x2986, pair := 0x2985, bracketType := .Close },
  { codepoint := 0x2987, pair := 0x2988, bracketType := .Open },
  { codepoint := 0x2988, pair := 0x2987, bracketType := .Close },
  { codepoint := 0x2989, pair := 0x298A, bracketType := .Open },
  { codepoint := 0x298A, pair := 0x2989, bracketType := .Close },
  { codepoint := 0x298B, pair := 0x298C, bracketType := .Open },
  { codepoint := 0x298C, pair := 0x298B, bracketType := .Close },
  { codepoint := 0x298D, pair := 0x2990, bracketType := .Open },
  { codepoint := 0x298E, pair := 0x298F, bracketType := .Close },
  { codepoint := 0x298F, pair := 0x298E, bracketType := .Open },
  { codepoint := 0x2990, pair := 0x298D, bracketType := .Close },
  { codepoint := 0x2991, pair := 0x2992, bracketType := .Open },
  { codepoint := 0x2992, pair := 0x2991, bracketType := .Close },
  { codepoint := 0x2993, pair := 0x2994, bracketType := .Open },
  { codepoint := 0x2994, pair := 0x2993, bracketType := .Close },
  { codepoint := 0x2995, pair := 0x2996, bracketType := .Open },
  { codepoint := 0x2996, pair := 0x2995, bracketType := .Close },
  { codepoint := 0x2997, pair := 0x2998, bracketType := .Open },
  { codepoint := 0x2998, pair := 0x2997, bracketType := .Close },
  { codepoint := 0x29D8, pair := 0x29D9, bracketType := .Open },
  { codepoint := 0x29D9, pair := 0x29D8, bracketType := .Close },
  { codepoint := 0x29DA, pair := 0x29DB, bracketType := .Open },
  { codepoint := 0x29DB, pair := 0x29DA, bracketType := .Close },
  { codepoint := 0x29FC, pair := 0x29FD, bracketType := .Open },
  { codepoint := 0x29FD, pair := 0x29FC, bracketType := .Close },
  { codepoint := 0x2E22, pair := 0x2E23, bracketType := .Open },
  { codepoint := 0x2E23, pair := 0x2E22, bracketType := .Close },
  { codepoint := 0x2E24, pair := 0x2E25, bracketType := .Open },
  { codepoint := 0x2E25, pair := 0x2E24, bracketType := .Close },
  { codepoint := 0x2E26, pair := 0x2E27, bracketType := .Open },
  { codepoint := 0x2E27, pair := 0x2E26, bracketType := .Close },
  { codepoint := 0x2E28, pair := 0x2E29, bracketType := .Open },
  { codepoint := 0x2E29, pair := 0x2E28, bracketType := .Close },
  { codepoint := 0x2E55, pair := 0x2E56, bracketType := .Open },
  { codepoint := 0x2E56, pair := 0x2E55, bracketType := .Close },
  { codepoint := 0x2E57, pair := 0x2E58, bracketType := .Open },
  { codepoint := 0x2E58, pair := 0x2E57, bracketType := .Close },
  { codepoint := 0x2E59, pair := 0x2E5A, bracketType := .Open },
  { codepoint := 0x2E5A, pair := 0x2E59, bracketType := .Close },
  { codepoint := 0x2E5B, pair := 0x2E5C, bracketType := .Open },
  { codepoint := 0x2E5C, pair := 0x2E5B, bracketType := .Close },
  { codepoint := 0x3008, pair := 0x3009, bracketType := .Open },
  { codepoint := 0x3009, pair := 0x3008, bracketType := .Close },
  { codepoint := 0x300A, pair := 0x300B, bracketType := .Open },
  { codepoint := 0x300B, pair := 0x300A, bracketType := .Close },
  { codepoint := 0x300C, pair := 0x300D, bracketType := .Open },
  { codepoint := 0x300D, pair := 0x300C, bracketType := .Close },
  { codepoint := 0x300E, pair := 0x300F, bracketType := .Open },
  { codepoint := 0x300F, pair := 0x300E, bracketType := .Close },
  { codepoint := 0x3010, pair := 0x3011, bracketType := .Open },
  { codepoint := 0x3011, pair := 0x3010, bracketType := .Close },
  { codepoint := 0x3014, pair := 0x3015, bracketType := .Open },
  { codepoint := 0x3015, pair := 0x3014, bracketType := .Close },
  { codepoint := 0x3016, pair := 0x3017, bracketType := .Open },
  { codepoint := 0x3017, pair := 0x3016, bracketType := .Close },
  { codepoint := 0x3018, pair := 0x3019, bracketType := .Open },
  { codepoint := 0x3019, pair := 0x3018, bracketType := .Close },
  { codepoint := 0x301A, pair := 0x301B, bracketType := .Open },
  { codepoint := 0x301B, pair := 0x301A, bracketType := .Close },
  { codepoint := 0xFE59, pair := 0xFE5A, bracketType := .Open },
  { codepoint := 0xFE5A, pair := 0xFE59, bracketType := .Close },
  { codepoint := 0xFE5B, pair := 0xFE5C, bracketType := .Open },
  { codepoint := 0xFE5C, pair := 0xFE5B, bracketType := .Close },
  { codepoint := 0xFE5D, pair := 0xFE5E, bracketType := .Open },
  { codepoint := 0xFE5E, pair := 0xFE5D, bracketType := .Close },
  { codepoint := 0xFF08, pair := 0xFF09, bracketType := .Open },
  { codepoint := 0xFF09, pair := 0xFF08, bracketType := .Close },
  { codepoint := 0xFF3B, pair := 0xFF3D, bracketType := .Open },
  { codepoint := 0xFF3D, pair := 0xFF3B, bracketType := .Close },
  { codepoint := 0xFF5B, pair := 0xFF5D, bracketType := .Open },
  { codepoint := 0xFF5D, pair := 0xFF5B, bracketType := .Close },
  { codepoint := 0xFF5F, pair := 0xFF60, bracketType := .Open },
  { codepoint := 0xFF60, pair := 0xFF5F, bracketType := .Close },
  { codepoint := 0xFF62, pair := 0xFF63, bracketType := .Open },
  { codepoint := 0xFF63, pair := 0xFF62, bracketType := .Close }
]

def binarySearch (cp : Nat) (left right fuel : Nat) : Option BidiBracketRow :=
  match fuel with
  | 0 => none
  | fuelNext + 1 =>
    if left < right then
      let mid := (left + right) / 2
      let row := bidiBracketRows[mid]!
      if cp < row.codepoint then binarySearch cp left mid fuelNext
      else if row.codepoint < cp then binarySearch cp (mid + 1) right fuelNext
      else some row
    else none

def lookup? (cp : Nat) : Option BidiBracketRow :=
  binarySearch cp 0 bidiBracketRows.length (bidiBracketRows.length + 1)

theorem lookup_u0028 :
    lookup? 0x0028 = some { codepoint := 0x0028, pair := 0x0029, bracketType := .Open } := by decide

-- INTEGRITY GATE — `bidiBracketRows` must equal a fresh parse of BidiBrackets.txt.
/-- Raw text of `BidiBrackets.txt`, embedded at compile time. -/
def bidiBracketsRaw : String := include_str "../Ucd/BidiBrackets.txt"
def bHexVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

def bHex (s : String) : Nat := s.foldl (fun acc c => acc * 16 + bHexVal c) 0

def bTrim (s : String) : String := (String.trimAscii s).toString

def bStrip (line : String) : String := bTrim ((line.takeWhile (· != '#')).toString)

def bbParse (line : String) : Option BidiBracketRow :=
  let s := bStrip line
  if s.isEmpty then none else
  match (s.splitOn ";") with
  | [a, b, t] =>
    let bt := bTrim t
    if bt == "o" then some { codepoint := bHex (bTrim a), pair := bHex (bTrim b), bracketType := .Open }
    else if bt == "c" then some { codepoint := bHex (bTrim a), pair := bHex (bTrim b), bracketType := .Close }
    else none
  | _other => none

def bidiBracketRowsParsed : List BidiBracketRow :=
  ((bidiBracketsRaw.splitOn "\n").filterMap bbParse)

#eval do
  unless bidiBracketRows == bidiBracketRowsParsed do
    throw (IO.userError "BidiBrackets drift: bidiBracketRows ≠ parsed BidiBrackets.txt")

end Unicode.Generated.BidiBrackets
