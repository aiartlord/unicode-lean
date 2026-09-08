/-
  Unicode.Generated.IntentionalConfusables

  Generated from Unicode/Ucd/intentional.txt.
  Do not edit by hand; run
  scripts/internal/generate_intentional_confusables_lean.py.
-/

namespace Unicode.Generated.IntentionalConfusables

/-! UTS #39 intentional-confusable pairs.  Each entry `(source, target)`
    names two code points whose confusability the Unicode Consortium
    designates as intentional.  A source code point may appear in more
    than one pair. -/

def pairs : List (Nat × Nat) := [
  (0x21, 0x1C3),
  (0x41, 0x391),
  (0x42, 0x392),
  (0x43, 0x421),
  (0x45, 0x395),
  (0x48, 0x397),
  (0x49, 0x399),
  (0x4A, 0x408),
  (0x4B, 0x39A),
  (0x4D, 0x39C),
  (0x4E, 0x39D),
  (0x4F, 0x39F),
  (0x50, 0x3A1),
  (0x53, 0x405),
  (0x54, 0x3A4),
  (0x58, 0x3A7),
  (0x59, 0x3A5),
  (0x5A, 0x396),
  (0x61, 0x430),
  (0x63, 0x441),
  (0x64, 0x501),
  (0x65, 0x435),
  (0x68, 0x4BB),
  (0x69, 0x456),
  (0x6A, 0x3F3),
  (0x6F, 0x3BF),
  (0x70, 0x440),
  (0x73, 0x455),
  (0x78, 0x445),
  (0x79, 0x443),
  (0xC6, 0x4D4),
  (0xD0, 0x110),
  (0xE6, 0x4D5),
  (0x138, 0x43A),
  (0x182, 0x411),
  (0x18F, 0x4D8),
  (0x19F, 0x4E8),
  (0x1A9, 0x3A3),
  (0x1DD, 0x259),
  (0x245, 0x39B),
  (0x259, 0x4D9),
  (0x25B, 0x3B5),
  (0x269, 0x3B9),
  (0x275, 0x4E9),
  (0x292, 0x4E1),
  (0x299, 0x432),
  (0x29C, 0x43D),
  (0x393, 0x413),
  (0x3A0, 0x41F),
  (0x3B1, 0x237A),
  (0x3B9, 0x2373),
  (0x3C1, 0x2374),
  (0x3C9, 0x2375),
  (0x433, 0x1D26),
  (0x43B, 0x1D2B),
  (0x43F, 0x1D28),
  (0x101D, 0x1040),
  (0x17A2, 0x17A3),
  (0x1835, 0x1855),
  (0x199E, 0x19D0),
  (0x19B1, 0x19D1),
  (0x1A45, 0x1A80),
  (0x1A45, 0x1A90),
  (0x1B0D, 0x1B52),
  (0x1B11, 0x1B53),
  (0x1B28, 0x1B58),
  (0x1B50, 0x1B5C),
  (0x1D0D, 0x43C),
  (0x1D18, 0x1D29),
  (0x1D1B, 0x442),
  (0x2C67, 0x4A2),
  (0x2C69, 0x49A),
  (0xA9D0, 0xA9C6),
  (0x10382, 0x103D1),
  (0x10393, 0x103D3),
  (0x1039A, 0x12038),
  (0x10486, 0x104A0)
]

def pairsCount : Nat := 77

/-! Canonical representative of each intentional-confusable class: the
    least code point in the class.  The map is the identity outside the
    classes, and every class's least member is its ASCII or lowest-Latin
    letter, so it is the identity on ASCII and never rewrites an ordinary
    identifier.  Applying it before the skeleton folds a class member to
    its representative, collapsing the capital cross-script look-alikes
    that the case-folding skeleton keeps apart. -/
def canonicalRep (cp : Nat) : Nat :=
  if cp < 0x455 then
    if cp < 0x3B5 then
      if cp < 0x39A then
        if cp < 0x392 then
          if cp < 0x259 then
            if cp < 0x1C3 then
              if cp < 0x110 then
                cp
              else if 0x110 < cp then
                cp
              else 0xD0
            else if 0x1C3 < cp then
              cp
            else 0x21
          else if 0x259 < cp then
            if cp < 0x391 then
              cp
            else if 0x391 < cp then
              cp
            else 0x41
          else 0x1DD
        else if 0x392 < cp then
          if cp < 0x397 then
            if cp < 0x396 then
              if cp < 0x395 then
                cp
              else if 0x395 < cp then
                cp
              else 0x45
            else if 0x396 < cp then
              cp
            else 0x5A
          else if 0x397 < cp then
            if cp < 0x399 then
              cp
            else if 0x399 < cp then
              cp
            else 0x49
          else 0x48
        else 0x42
      else if 0x39A < cp then
        if cp < 0x3A1 then
          if cp < 0x39D then
            if cp < 0x39C then
              if cp < 0x39B then
                cp
              else if 0x39B < cp then
                cp
              else 0x245
            else if 0x39C < cp then
              cp
            else 0x4D
          else if 0x39D < cp then
            if cp < 0x39F then
              cp
            else if 0x39F < cp then
              cp
            else 0x4F
          else 0x4E
        else if 0x3A1 < cp then
          if cp < 0x3A5 then
            if cp < 0x3A4 then
              if cp < 0x3A3 then
                cp
              else if 0x3A3 < cp then
                cp
              else 0x1A9
            else if 0x3A4 < cp then
              cp
            else 0x54
          else if 0x3A5 < cp then
            if cp < 0x3A7 then
              cp
            else if 0x3A7 < cp then
              cp
            else 0x58
          else 0x59
        else 0x50
      else 0x4B
    else if 0x3B5 < cp then
      if cp < 0x430 then
        if cp < 0x408 then
          if cp < 0x3F3 then
            if cp < 0x3BF then
              if cp < 0x3B9 then
                cp
              else if 0x3B9 < cp then
                cp
              else 0x269
            else if 0x3BF < cp then
              cp
            else 0x6F
          else if 0x3F3 < cp then
            if cp < 0x405 then
              cp
            else if 0x405 < cp then
              cp
            else 0x53
          else 0x6A
        else if 0x408 < cp then
          if cp < 0x41F then
            if cp < 0x413 then
              if cp < 0x411 then
                cp
              else if 0x411 < cp then
                cp
              else 0x182
            else if 0x413 < cp then
              cp
            else 0x393
          else if 0x41F < cp then
            if cp < 0x421 then
              cp
            else if 0x421 < cp then
              cp
            else 0x43
          else 0x3A0
        else 0x4A
      else if 0x430 < cp then
        if cp < 0x440 then
          if cp < 0x43A then
            if cp < 0x435 then
              if cp < 0x432 then
                cp
              else if 0x432 < cp then
                cp
              else 0x299
            else if 0x435 < cp then
              cp
            else 0x65
          else if 0x43A < cp then
            if cp < 0x43D then
              cp
            else if 0x43D < cp then
              cp
            else 0x29C
          else 0x138
        else if 0x440 < cp then
          if cp < 0x443 then
            if cp < 0x441 then
              cp
            else if 0x441 < cp then
              cp
            else 0x63
          else if 0x443 < cp then
            if cp < 0x445 then
              cp
            else if 0x445 < cp then
              cp
            else 0x78
          else 0x79
        else 0x70
      else 0x61
    else 0x25B
  else if 0x455 < cp then
    if cp < 0x1B58 then
      if cp < 0x501 then
        if cp < 0x4D8 then
          if cp < 0x4D4 then
            if cp < 0x4BB then
              if cp < 0x456 then
                cp
              else if 0x456 < cp then
                cp
              else 0x69
            else if 0x4BB < cp then
              cp
            else 0x68
          else if 0x4D4 < cp then
            if cp < 0x4D5 then
              cp
            else if 0x4D5 < cp then
              cp
            else 0xE6
          else 0xC6
        else if 0x4D8 < cp then
          if cp < 0x4E8 then
            if cp < 0x4E1 then
              if cp < 0x4D9 then
                cp
              else if 0x4D9 < cp then
                cp
              else 0x1DD
            else if 0x4E1 < cp then
              cp
            else 0x292
          else if 0x4E8 < cp then
            if cp < 0x4E9 then
              cp
            else if 0x4E9 < cp then
              cp
            else 0x275
          else 0x19F
        else 0x18F
      else if 0x501 < cp then
        if cp < 0x19D1 then
          if cp < 0x1855 then
            if cp < 0x17A3 then
              if cp < 0x1040 then
                cp
              else if 0x1040 < cp then
                cp
              else 0x101D
            else if 0x17A3 < cp then
              cp
            else 0x17A2
          else if 0x1855 < cp then
            if cp < 0x19D0 then
              cp
            else if 0x19D0 < cp then
              cp
            else 0x199E
          else 0x1835
        else if 0x19D1 < cp then
          if cp < 0x1B52 then
            if cp < 0x1A90 then
              if cp < 0x1A80 then
                cp
              else if 0x1A80 < cp then
                cp
              else 0x1A45
            else if 0x1A90 < cp then
              cp
            else 0x1A45
          else if 0x1B52 < cp then
            if cp < 0x1B53 then
              cp
            else if 0x1B53 < cp then
              cp
            else 0x1B11
          else 0x1B0D
        else 0x19B1
      else 0x64
    else if 0x1B58 < cp then
      if cp < 0x2375 then
        if cp < 0x1D28 then
          if cp < 0x1D1B then
            if cp < 0x1D0D then
              if cp < 0x1B5C then
                cp
              else if 0x1B5C < cp then
                cp
              else 0x1B50
            else if 0x1D0D < cp then
              cp
            else 0x43C
          else if 0x1D1B < cp then
            if cp < 0x1D26 then
              cp
            else if 0x1D26 < cp then
              cp
            else 0x433
          else 0x442
        else if 0x1D28 < cp then
          if cp < 0x2373 then
            if cp < 0x1D2B then
              if cp < 0x1D29 then
                cp
              else if 0x1D29 < cp then
                cp
              else 0x1D18
            else if 0x1D2B < cp then
              cp
            else 0x43B
          else if 0x2373 < cp then
            if cp < 0x2374 then
              cp
            else if 0x2374 < cp then
              cp
            else 0x3C1
          else 0x269
        else 0x43F
      else if 0x2375 < cp then
        if cp < 0x103D1 then
          if cp < 0x2C69 then
            if cp < 0x2C67 then
              if cp < 0x237A then
                cp
              else if 0x237A < cp then
                cp
              else 0x3B1
            else if 0x2C67 < cp then
              cp
            else 0x4A2
          else if 0x2C69 < cp then
            if cp < 0xA9D0 then
              cp
            else if 0xA9D0 < cp then
              cp
            else 0xA9C6
          else 0x49A
        else if 0x103D1 < cp then
          if cp < 0x104A0 then
            if cp < 0x103D3 then
              cp
            else if 0x103D3 < cp then
              cp
            else 0x10393
          else if 0x104A0 < cp then
            if cp < 0x12038 then
              cp
            else if 0x12038 < cp then
              cp
            else 0x1039A
          else 0x10486
        else 0x10382
      else 0x3C9
    else 0x1B28
  else 0x73

end Unicode.Generated.IntentionalConfusables
