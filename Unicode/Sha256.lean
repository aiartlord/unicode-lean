/-
  Unicode.Sha256

  A self-contained SHA-256 (FIPS 180-4) over `ByteArray`, used to verify
  at build time that each pinned UCD source file hashes to its recorded
  digest. This turns the digest manifest from a passive record into an
  enforced gate: a tampered or version-drifted `.txt` changes its hash and
  aborts the build.

  The implementation is deliberately plain — `UInt32` wrapping arithmetic
  over the message schedule and compression function, no external code.
-/

namespace Unicode.Sha256

/-- The 64 SHA-256 round constants (FIPS 180-4 §4.2.2): the first 32 bits of
    the fractional parts of the cube roots of the first 64 primes. -/
def roundConstants : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

/-- Initial hash value (FIPS 180-4 §5.3.3): fractional parts of the square
    roots of the first 8 primes. -/
def initialHash : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

/-- 32-bit right rotate. -/
@[inline] def rotr (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))

/-- Pad the message per FIPS 180-4 §5.1.1: append `0x80`, then zeros, then the
    64-bit big-endian bit length, to a multiple of 64 bytes. -/
def pad (msg : ByteArray) : ByteArray := Id.run do
  let bitLen : UInt64 := (UInt64.ofNat msg.size) * 8
  let mut out := msg.push 0x80
  while out.size % 64 != 56 do
    out := out.push 0x00
  for i in [0:8] do
    out := out.push (UInt8.ofNat ((bitLen >>> (UInt64.ofNat ((7 - i) * 8))).toNat % 256))
  return out

/-- Big-endian read of 4 bytes at `off` as a `UInt32`. -/
@[inline] def beWord (b : ByteArray) (off : Nat) : UInt32 :=
  (UInt32.ofNat (b.get! off).toNat <<< 24) |||
  (UInt32.ofNat (b.get! (off+1)).toNat <<< 16) |||
  (UInt32.ofNat (b.get! (off+2)).toNat <<< 8) |||
  (UInt32.ofNat (b.get! (off+3)).toNat)

/-- Compress one 64-byte block starting at `off` into the running state `hv`. -/
def compressBlock (b : ByteArray) (off : Nat) (hv : Array UInt32) : Array UInt32 := Id.run do
  let mut w : Array UInt32 := Array.replicate 64 0
  for t in [0:16] do
    w := w.set! t (beWord b (off + t*4))
  for t in [16:64] do
    let s0 := rotr w[t-15]! 7 ^^^ rotr w[t-15]! 18 ^^^ (w[t-15]! >>> 3)
    let s1 := rotr w[t-2]! 17 ^^^ rotr w[t-2]! 19 ^^^ (w[t-2]! >>> 10)
    w := w.set! t (w[t-16]! + s0 + w[t-7]! + s1)
  let mut a := hv[0]!
  let mut bb := hv[1]!
  let mut c := hv[2]!
  let mut d := hv[3]!
  let mut e := hv[4]!
  let mut f := hv[5]!
  let mut g := hv[6]!
  let mut h := hv[7]!
  for t in [0:64] do
    let s1 := rotr e 6 ^^^ rotr e 11 ^^^ rotr e 25
    let ch := (e &&& f) ^^^ ((~~~e) &&& g)
    let temp1 := h + s1 + ch + roundConstants[t]! + w[t]!
    let s0 := rotr a 2 ^^^ rotr a 13 ^^^ rotr a 22
    let maj := (a &&& bb) ^^^ (a &&& c) ^^^ (bb &&& c)
    let temp2 := s0 + maj
    h := g; g := f; f := e; e := d + temp1
    d := c; c := bb; bb := a; a := temp1 + temp2
  return #[hv[0]! + a, hv[1]! + bb, hv[2]! + c, hv[3]! + d,
           hv[4]! + e, hv[5]! + f, hv[6]! + g, hv[7]! + h]

/-- A nibble (0–15) as its lowercase hex character. -/
def hexDigit (nib : Nat) : Char :=
  if nib < 10 then Char.ofNat (0x30 + nib) else Char.ofNat (0x61 + (nib - 10))

/-- One `UInt32` as 8 lowercase hex digits, big-endian. -/
def wordHex (x : UInt32) : String := Id.run do
  let mut s := ""
  for i in [0:8] do
    let nib := (x >>> (UInt32.ofNat ((7 - i) * 4))).toNat % 16
    s := s.push (hexDigit nib)
  return s

/-- SHA-256 digest of `msg` as a 64-character lowercase hex string. -/
def hashHex (msg : ByteArray) : String := Id.run do
  let padded := pad msg
  let mut hv := initialHash
  let mut off := 0
  while off < padded.size do
    hv := compressBlock padded off hv
    off := off + 64
  let mut out := ""
  for i in [0:8] do
    out := out ++ wordHex hv[i]!
  return out

/-- SHA-256 of a `String`'s UTF-8 encoding. -/
def hashStringHex (s : String) : String := hashHex s.toUTF8

end Unicode.Sha256
