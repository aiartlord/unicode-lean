/-
  Unicode.Idna.Punycode

  RFC 3492 — Punycode: a Bootstring encoding of Unicode for
  Internationalized Domain Names in Applications (IDNA). Punycode
  is a one-to-one encoding between Unicode strings (with at least
  one non-basic codepoint) and their ASCII Punycode form. The
  "xn--" ACE prefix is added by the IDNA layer (UTS #46), not by
  Punycode itself.

  Sample test vectors are taken from RFC 3492 §7.1.
-/

namespace Unicode.Idna.Punycode

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 BOOTSTRING PARAMETERS  (RFC 3492 §5)
-- ═══════════════════════════════════════════════════════════════════════════════

def base        : Nat := 36
def tmin        : Nat := 1
def tmax        : Nat := 26
def skew        : Nat := 38
def damp        : Nat := 700
def initialBias : Nat := 72
def initialN    : Nat := 128

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 DIGIT ENCODE / DECODE  (RFC 3492 §5)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Encode a digit in [0, 36) as 'a'..'z' (0..25) or '0'..'9' (26..35). -/
def encodeDigit (d : Nat) : Char :=
  if d < 26 then Char.ofNat (d + 'a'.toNat)
  else if d < 36 then Char.ofNat (d - 26 + '0'.toNat)
  else 'a'

/-- Decode an ASCII char to a base-36 digit (case-insensitive A..Z = a..z =
    0..25; 0..9 = 26..35). Returns `none` if the char is not a valid digit. -/
def decodeDigit (c : Char) : Option Nat :=
  let n := c.toNat
  if 'A'.toNat ≤ n ∧ n ≤ 'Z'.toNat then some (n - 'A'.toNat)
  else if 'a'.toNat ≤ n ∧ n ≤ 'z'.toNat then some (n - 'a'.toNat)
  else if '0'.toNat ≤ n ∧ n ≤ '9'.toNat then some (n - '0'.toNat + 26)
  else none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 BIAS ADAPTATION  (RFC 3492 §6.1)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Inner loop of `adapt`. Each iteration divides delta by `base - tmin = 35`,
    so 64 iterations cover deltas up to 35^64 ≈ 10^99 — well beyond any
    reachable input. -/
def adaptLoop (fuel delta k : Nat) : Nat :=
  match fuel with
  | 0       => k + (((base - tmin + 1) * delta) / (delta + skew))
  | fuel+1  =>
    if delta > ((base - tmin) * tmax) / 2 then
      adaptLoop fuel (delta / (base - tmin)) (k + base)
    else k + (((base - tmin + 1) * delta) / (delta + skew))

/-- Bias adaptation (RFC 3492 §6.1). -/
def adapt (delta numpoints : Nat) (firsttime : Bool) : Nat :=
  let delta1 := if firsttime then delta / damp else delta / 2
  let delta2 := delta1 + delta1 / numpoints
  adaptLoop 64 delta2 0

/-- Threshold from RFC 3492 §6.2 / §6.3: `clamp(k - bias, tmin, tmax)`,
    written so subtraction stays in `Nat`. -/
@[inline]
def threshold (k bias : Nat) : Nat :=
  if k ≤ bias + tmin      then tmin
  else if k ≥ bias + tmax then tmax
  else k - bias

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 ENCODE  (RFC 3492 §6.3)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Inner q-loop of encode: emit base-36 digits for `q` with `bias`. -/
def encodeQ (fuel q k bias : Nat) (acc : String) : String :=
  match fuel with
  | 0      => acc.push (encodeDigit q)
  | fuel+1 =>
    let t := threshold k bias
    if q < t then acc.push (encodeDigit q)
    else
      let d := t + (q - t) % (base - t)
      encodeQ fuel ((q - t) / (base - t)) (k + base) bias (acc.push (encodeDigit d))

/-- For the current threshold `n`, walk every codepoint in `input` and emit
    a digit run for each occurrence of `n`, accumulating the running
    `(output, h, delta, bias)`. -/
def encodeProcess (input : List Nat) (n h delta bias b : Nat) (acc : String) :
    String × Nat × Nat × Nat := Id.run do
  let mut acc'   := acc
  let mut h'     := h
  let mut delta' := delta
  let mut bias'  := bias
  for cp in input do
    if cp < n then
      delta' := delta' + 1
    else if cp == n then
      acc'   := encodeQ 64 delta' base bias' acc'
      bias'  := adapt delta' (h' + 1) (h' == b)
      delta' := 0
      h'     := h' + 1
  return (acc', h', delta', bias')

/-- Find the smallest codepoint in `input` that is ≥ `n`. -/
def minGE (input : List Nat) (n : Nat) : Option Nat :=
  input.foldl (fun a cp =>
    if cp ≥ n then
      match a with
      | none   => some cp
      | some m => some (Nat.min m cp)
    else a) none

/-- Outer encode loop, fuelled. Each iteration strictly increases `n`, so
    fuel `0x110001` is sufficient for any well-formed Unicode input. -/
def encodeOuter (fuel : Nat) (input : List Nat) (n h delta bias b : Nat)
    (acc : String) : Option String :=
  if h ≥ input.length then some acc
  else match fuel with
    | 0       => none
    | fuel+1  =>
      match minGE input n with
      | none   => none
      | some m =>
        let delta1 := delta + (m - n) * (h + 1)
        let (acc', h', delta', bias') := encodeProcess input m h delta1 bias b acc
        encodeOuter fuel input (m + 1) h' (delta' + 1) bias' b acc'

/-- Encode an array of Unicode codepoints to its Punycode form. Returns
    `none` only on internal logic errors (the underlying algorithm is
    deterministic and total on well-formed input). -/
def encode (input : List Nat) : Option String := Id.run do
  let mut acc : String := ""
  let mut b   : Nat    := 0
  for cp in input do
    if cp < 0x80 then
      acc := acc.push (Char.ofNat cp)
      b   := b + 1
  if 0 < b ∧ b < input.length then
    acc := acc.push '-'
  return encodeOuter (input.length + 1) input initialN b 0 initialBias b acc

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 DECODE  (RFC 3492 §6.2)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Inner k-loop of decode: read base-36 digits, accumulate into `i` with
    weight `w`. Returns `(i, pos)` after consumption, or `none` on bad input. -/
def decodeQ (fuel : Nat) (chars : List Char) (pos i w k bias : Nat) :
    Option (Nat × Nat) :=
  match fuel with
  | 0       => none
  | fuel+1  =>
    match chars[pos]? with
    | none   => none
    | some c =>
      match decodeDigit c with
      | none       => none
      | some digit =>
        let i' := i + digit * w
        let t := threshold k bias
        if digit < t then some (i', pos + 1)
        else decodeQ fuel chars (pos + 1) i' (w * (base - t)) (k + base) bias

/-- Insert `x` at index `i` in `arr` (clamping to the end if `i ≥ arr.length`). -/
def insertAt (arr : List Nat) (i : Nat) (x : Nat) : List Nat :=
  let n := arr.length
  if i ≥ n then arr ++ [x]
  else (arr.take i ++ [x]) ++ arr.drop i

/-- Outer decode loop, fuelled. Each iteration consumes ≥ 1 character. -/
def decodeOuter (fuel : Nat) (chars : List Char) (pos n i bias : Nat)
    (output : List Nat) : Option (List Nat) :=
  if pos ≥ chars.length then some output
  else match fuel with
    | 0       => none
    | fuel+1  =>
      let oldi := i
      match decodeQ 64 chars pos i 1 base bias with
      | none            => none
      | some (i', pos') =>
        let bias'  := adapt (i' - oldi) (output.length + 1) (oldi == 0)
        let nDelta := i' / (output.length + 1)
        let i''    := i' % (output.length + 1)
        let n'     := n + nDelta
        if 0x10FFFF < n' then none
        else decodeOuter fuel chars pos' n' (i'' + 1) bias' (insertAt output i'' n')

/-- Find the index of the last '-' in `chars`, or `none`. -/
def findLastDelim (chars : List Char) : Option Nat :=
  (chars.foldl (fun (s : Nat × Option Nat) c =>
    let (i, acc) := s
    let acc' := if c == '-' then some i else acc
    (i + 1, acc')) (0, none)).snd

/-- Decode a Punycode string to an array of Unicode codepoints. -/
def decode (input : String) : Option (List Nat) :=
  let chars := input.toList
  match findLastDelim chars with
  | none =>
    decodeOuter (chars.length + 1) chars 0 initialN 0 initialBias []
  | some idx =>
    let basicArr : List Char := chars.take idx
    if basicArr.any (fun c => c.toNat ≥ 0x80) then none
    else
      let basic : List Nat := basicArr.map Char.toNat
      decodeOuter (chars.length + 1) chars (idx + 1) initialN 0 initialBias basic

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 RFC 3492 §7.1 SAMPLE STRINGS
-- ═══════════════════════════════════════════════════════════════════════════════

-- The sample encodings run the RFC 3492 main loop, whose bias variable climbs
-- to the largest non-basic codepoint (tens of thousands of iterations, each
-- scanning the whole input). Closing these with `decide +kernel` runs that loop
-- in the kernel with GMP-backed Nat arithmetic and bounded memory, instead of
-- the elaborator whnf which retains a thunk per step.
set_option maxRecDepth 100000

/-- Empty input round-trips trivially. -/
theorem encode_empty : encode [] = some "" := by decide
theorem decode_empty : decode "" = some [] := by decide

/-- (B) Chinese (simplified). All-non-basic input. -/
theorem encode_sample_B :
    encode [0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48,
             0x4E0D, 0x8BF4, 0x4E2D, 0x6587]
      = some "ihqwcrb4cv8a8dqg056pqjye" := by decide +kernel

theorem decode_sample_B :
    decode "ihqwcrb4cv8a8dqg056pqjye"
      = some [0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48,
               0x4E0D, 0x8BF4, 0x4E2D, 0x6587] := by decide +kernel

/-- (C) Chinese (traditional). -/
theorem encode_sample_C :
    encode [0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD,
             0x4E0D, 0x8AAA, 0x4E2D, 0x6587]
      = some "ihqwctvzc91f659drss3x8bo0yb" := by decide +kernel

theorem decode_sample_C :
    decode "ihqwctvzc91f659drss3x8bo0yb"
      = some [0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD,
               0x4E0D, 0x8AAA, 0x4E2D, 0x6587] := by decide +kernel

/-- (J) Spanish: mixed basic and non-basic codepoints. -/
theorem encode_sample_J :
    encode [0x50, 0x6F, 0x72, 0x71, 0x75, 0xE9, 0x6E, 0x6F,
             0x70, 0x75, 0x65, 0x64, 0x65, 0x6E, 0x73, 0x69,
             0x6D, 0x70, 0x6C, 0x65, 0x6D, 0x65, 0x6E, 0x74,
             0x65, 0x68, 0x61, 0x62, 0x6C, 0x61, 0x72, 0x65,
             0x6E, 0x45, 0x73, 0x70, 0x61, 0xF1, 0x6F, 0x6C]
      = some "PorqunopuedensimplementehablarenEspaol-fmd56a" := by decide +kernel

theorem decode_sample_J :
    decode "PorqunopuedensimplementehablarenEspaol-fmd56a"
      = some [0x50, 0x6F, 0x72, 0x71, 0x75, 0xE9, 0x6E, 0x6F,
               0x70, 0x75, 0x65, 0x64, 0x65, 0x6E, 0x73, 0x69,
               0x6D, 0x70, 0x6C, 0x65, 0x6D, 0x65, 0x6E, 0x74,
               0x65, 0x68, 0x61, 0x62, 0x6C, 0x61, 0x72, 0x65,
               0x6E, 0x45, 0x73, 0x70, 0x61, 0xF1, 0x6F, 0x6C] := by decide +kernel

end Unicode.Idna.Punycode
