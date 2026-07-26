/-
  Unicode.Generated.ScriptExtensionsData

  Materialized Script_Extensions range table (UCD 17.0.0), pinned as a
  `List` literal so per-codepoint lookups reduce in the kernel. The
  parser and `include_str` source live in
  `Unicode.Generated.ScriptExtensions`, which imports this module and
  carries the build-time drift gate. The `ScriptAbbrev` type is defined
  here to avoid a circular import.
-/

namespace Unicode.Generated.ScriptExtensions

set_option maxRecDepth 1000000

inductive ScriptAbbrev where
  | Adlm
  | Aghb
  | Arab
  | Armn
  | Avst
  | Beng
  | Bopo
  | Bugi
  | Buhd
  | Cakm
  | Cari
  | Cher
  | Copt
  | Cpmn
  | Cprt
  | Cyrl
  | Deva
  | Dogr
  | Dupl
  | Elba
  | Ethi
  | Gara
  | Geor
  | Glag
  | Gong
  | Gonm
  | Goth
  | Gran
  | Grek
  | Gujr
  | Gukh
  | Guru
  | Hang
  | Hani
  | Hano
  | Hebr
  | Hira
  | Hung
  | Java
  | Kali
  | Kana
  | Khoj
  | Knda
  | Kthi
  | Latn
  | Limb
  | Lina
  | Linb
  | Lisu
  | Lyci
  | Lydi
  | Mahj
  | Mand
  | Mani
  | Mero
  | Mlym
  | Modi
  | Mong
  | Mult
  | Mymr
  | Nand
  | Newa
  | Nkoo
  | Onao
  | Orkh
  | Orya
  | Osge
  | Ougr
  | Perm
  | Phag
  | Phlp
  | Rohg
  | Runr
  | Samr
  | Shaw
  | Shrd
  | Sind
  | Sinh
  | Sogd
  | Sunu
  | Sylo
  | Syrc
  | Tagb
  | Takr
  | Tale
  | Taml
  | Tang
  | Telu
  | Tfng
  | Tglg
  | Thaa
  | Thai
  | Tibt
  | Tirh
  | Todr
  | Toto
  | Tutg
  | Yezi
  | Yiii
  deriving DecidableEq, Repr, Inhabited

/-- Materialized (lo, hi, abbrevs) Script_Extensions ranges in UCD
    codepoint order. A `List.findSome?` over this table reduces linearly
    in the kernel. -/
def scriptExtensionRanges : List (Nat × Nat × List ScriptAbbrev) := [
  (183, 183, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Avst, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cari, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Elba, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Geor, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Goth, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lydi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Perm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shaw]),
  (700, 700, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lisu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thai, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Toto]),
  (711, 711, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (713, 715, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (717, 717, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lisu]),
  (727, 727, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thai]),
  (729, 729, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (768, 768, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Perm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sunu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tale]),
  (769, 769, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Osge, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sunu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tale, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Todr]),
  (770, 770, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tfng]),
  (771, 771, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sunu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thai]),
  (772, 772, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Aghb, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Goth, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Osge, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tfng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Todr]),
  (773, 773, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Elba, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Goth, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (774, 774, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Perm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tfng]),
  (775, 775, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hebr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Perm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tale, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tfng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Todr]),
  (776, 776, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Armn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Goth, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hebr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Perm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tale, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tfng]),
  (777, 777, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tfng]),
  (778, 778, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (779, 779, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Osge]),
  (780, 780, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tale]),
  (781, 781, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sunu]),
  (782, 782, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Ethi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (784, 784, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sunu]),
  (785, 785, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Todr]),
  (787, 787, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Perm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Todr]),
  (803, 803, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tfng]),
  (804, 804, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (805, 805, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (813, 813, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sunu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (814, 814, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (816, 816, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (817, 817, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Aghb, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cher, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Goth, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sunu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thai]),
  (834, 834, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek]),
  (837, 837, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek]),
  (856, 856, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Osge]),
  (862, 862, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Aghb, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Todr]),
  (867, 879, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (884, 884, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek]),
  (885, 885, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek]),
  (1155, 1155, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Perm]),
  (1156, 1156, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag]),
  (1157, 1158, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (1159, 1159, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag]),
  (1417, 1417, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Armn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Geor, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag]),
  (1548, 1548, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gara, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nkoo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Rohg, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thaa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yezi]),
  (1563, 1563, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gara, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nkoo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Rohg, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thaa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yezi]),
  (1564, 1564, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thaa]),
  (1567, 1567, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Adlm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gara, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nkoo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Rohg, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thaa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yezi]),
  (1600, 1600, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Adlm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Ougr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Phlp, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Rohg, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sogd, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (1611, 1621, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (1632, 1641, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thaa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yezi]),
  (1648, 1648, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (1748, 1748, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Rohg]),
  (2385, 2385, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mlym, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orya, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (2386, 2386, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mlym, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orya, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (2404, 2404, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gonm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mlym, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Onao, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orya, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sind, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sinh, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sylo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Takr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (2405, 2405, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gonm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gukh, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Limb, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mlym, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Onao, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orya, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sind, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sinh, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sylo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Takr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (2406, 2415, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kthi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj]),
  (2534, 2543, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cakm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sylo]),
  (2662, 2671, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mult]),
  (2790, 2799, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Khoj]),
  (3046, 3055, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (3056, 3058, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (3059, 3059, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (3302, 3311, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tutg]),
  (4160, 4169, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cakm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mymr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tale]),
  (4347, 4347, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Geor, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (5867, 5869, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Runr]),
  (5941, 5942, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Buhd, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hano, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tagb, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tglg]),
  (6146, 6147, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Phag]),
  (6149, 6149, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Phag]),
  (7376, 7376, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda]),
  (7377, 7377, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7378, 7378, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda]),
  (7379, 7379, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda]),
  (7380, 7380, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7381, 7381, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (7382, 7382, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu]),
  (7383, 7383, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd]),
  (7384, 7384, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu]),
  (7385, 7385, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd]),
  (7386, 7386, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mlym, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orya, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu]),
  (7387, 7387, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7388, 7389, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd]),
  (7390, 7391, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7392, 7392, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd]),
  (7393, 7393, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7394, 7394, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (7395, 7400, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7401, 7401, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa]),
  (7402, 7402, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd]),
  (7403, 7403, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa]),
  (7404, 7404, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7405, 7405, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Newa, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd]),
  (7406, 7409, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7410, 7410, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mlym, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orya, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sinh, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Telu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tutg]),
  (7411, 7411, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran]),
  (7412, 7412, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tutg]),
  (7413, 7414, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva]),
  (7415, 7415, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng]),
  (7416, 7417, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran]),
  (7418, 7418, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand]),
  (7616, 7617, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek]),
  (7672, 7672, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (7674, 7674, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Syrc]),
  (8239, 8239, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Phag]),
  (8271, 8271, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Adlm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab]),
  (8282, 8282, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cari, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Geor, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hung, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lyci, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orkh]),
  (8285, 8285, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cari, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Grek, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hung, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mero]),
  (8432, 8432, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (11799, 11799, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (11824, 11824, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Avst, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Orkh]),
  (11825, 11825, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Avst, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cari, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Geor, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hung, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kthi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lydi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Samr]),
  (11836, 11836, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl]),
  (11841, 11841, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Adlm, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hung]),
  (11843, 11843, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag]),
  (12272, 12287, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tang]),
  (12289, 12289, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12290, 12290, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Phag, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12291, 12291, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12294, 12294, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12296, 12296, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tibt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12297, 12297, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tibt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12298, 12298, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lisu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tibt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12299, 12299, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lisu, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mong, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tibt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12300, 12300, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12301, 12301, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12302, 12302, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12303, 12303, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12304, 12304, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12305, 12305, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12307, 12307, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12308, 12308, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12309, 12309, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12310, 12310, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12311, 12311, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12312, 12312, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12313, 12313, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12314, 12314, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12315, 12315, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12316, 12316, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12317, 12317, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12318, 12319, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12330, 12333, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12336, 12336, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12337, 12341, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12343, 12343, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12348, 12348, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12349, 12349, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12350, 12351, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12441, 12442, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12443, 12444, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12448, 12448, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12539, 12539, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (12540, 12540, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (12688, 12689, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12690, 12693, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12694, 12703, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12736, 12773, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12783, 12783, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tang]),
  (12832, 12841, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12842, 12871, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12928, 12937, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12938, 12976, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (12992, 13003, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (13055, 13055, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (13144, 13168, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (13179, 13183, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (13280, 13310, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (42607, 42607, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cyrl, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Glag]),
  (42752, 42759, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn]),
  (43056, 43058, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Khoj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kthi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mlym, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Modi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sind, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Takr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tutg]),
  (43059, 43061, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Khoj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Knda, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kthi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Modi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nand, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sind, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Takr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tutg]),
  (43062, 43063, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Khoj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kthi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Modi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sind, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Takr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (43064, 43064, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Khoj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kthi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Modi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Shrd, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sind, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Takr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (43065, 43065, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dogr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gujr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Guru, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Khoj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kthi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mahj, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Modi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Sind, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Takr, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tirh]),
  (43249, 43249, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Beng, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Tutg]),
  (43251, 43251, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Deva, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (43310, 43310, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kali, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Latn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mymr]),
  (43471, 43471, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bugi, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Java]),
  (64830, 64830, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nkoo]),
  (64831, 64831, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Nkoo]),
  (65010, 65010, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thaa]),
  (65021, 65021, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Thaa]),
  (65093, 65094, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (65377, 65377, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (65378, 65378, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (65379, 65379, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (65380, 65381, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Bopo, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hang, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Yiii]),
  (65392, 65392, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (65438, 65439, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hira, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Kana]),
  (65792, 65793, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cpmn, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cprt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Linb]),
  (65794, 65794, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cprt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Linb]),
  (65799, 65843, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cprt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Lina, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Linb]),
  (65847, 65855, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Cprt, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Linb]),
  (66272, 66272, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt]),
  (66273, 66299, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Arab, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Copt]),
  (68338, 68338, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Mani, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Ougr]),
  (70401, 70401, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (70403, 70403, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (70459, 70460, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (73680, 73681, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (73683, 73683, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Gran, Unicode.Generated.ScriptExtensions.ScriptAbbrev.Taml]),
  (113824, 113827, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Dupl]),
  (119648, 119665, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani]),
  (127568, 127569, [Unicode.Generated.ScriptExtensions.ScriptAbbrev.Hani])
]

end Unicode.Generated.ScriptExtensions
