/-
  Unicode.Generated.WidthCompatMappings

  Literal width-compatibility decomposition mappings extracted from
  UnicodeData.txt (UCD 17.0.0), plus a generated certified lookup.
-/

namespace Unicode.Generated.WidthCompatMappings

set_option maxRecDepth 100000

/-- Width-compatibility mappings from source codepoint to target sequence. -/
def widthCompatMappings : List (Nat × List Nat) := [
  (0x3000, [0x0020]),
  (0xFF01, [0x0021]),
  (0xFF02, [0x0022]),
  (0xFF03, [0x0023]),
  (0xFF04, [0x0024]),
  (0xFF05, [0x0025]),
  (0xFF06, [0x0026]),
  (0xFF07, [0x0027]),
  (0xFF08, [0x0028]),
  (0xFF09, [0x0029]),
  (0xFF0A, [0x002A]),
  (0xFF0B, [0x002B]),
  (0xFF0C, [0x002C]),
  (0xFF0D, [0x002D]),
  (0xFF0E, [0x002E]),
  (0xFF0F, [0x002F]),
  (0xFF10, [0x0030]),
  (0xFF11, [0x0031]),
  (0xFF12, [0x0032]),
  (0xFF13, [0x0033]),
  (0xFF14, [0x0034]),
  (0xFF15, [0x0035]),
  (0xFF16, [0x0036]),
  (0xFF17, [0x0037]),
  (0xFF18, [0x0038]),
  (0xFF19, [0x0039]),
  (0xFF1A, [0x003A]),
  (0xFF1B, [0x003B]),
  (0xFF1C, [0x003C]),
  (0xFF1D, [0x003D]),
  (0xFF1E, [0x003E]),
  (0xFF1F, [0x003F]),
  (0xFF20, [0x0040]),
  (0xFF21, [0x0041]),
  (0xFF22, [0x0042]),
  (0xFF23, [0x0043]),
  (0xFF24, [0x0044]),
  (0xFF25, [0x0045]),
  (0xFF26, [0x0046]),
  (0xFF27, [0x0047]),
  (0xFF28, [0x0048]),
  (0xFF29, [0x0049]),
  (0xFF2A, [0x004A]),
  (0xFF2B, [0x004B]),
  (0xFF2C, [0x004C]),
  (0xFF2D, [0x004D]),
  (0xFF2E, [0x004E]),
  (0xFF2F, [0x004F]),
  (0xFF30, [0x0050]),
  (0xFF31, [0x0051]),
  (0xFF32, [0x0052]),
  (0xFF33, [0x0053]),
  (0xFF34, [0x0054]),
  (0xFF35, [0x0055]),
  (0xFF36, [0x0056]),
  (0xFF37, [0x0057]),
  (0xFF38, [0x0058]),
  (0xFF39, [0x0059]),
  (0xFF3A, [0x005A]),
  (0xFF3B, [0x005B]),
  (0xFF3C, [0x005C]),
  (0xFF3D, [0x005D]),
  (0xFF3E, [0x005E]),
  (0xFF3F, [0x005F]),
  (0xFF40, [0x0060]),
  (0xFF41, [0x0061]),
  (0xFF42, [0x0062]),
  (0xFF43, [0x0063]),
  (0xFF44, [0x0064]),
  (0xFF45, [0x0065]),
  (0xFF46, [0x0066]),
  (0xFF47, [0x0067]),
  (0xFF48, [0x0068]),
  (0xFF49, [0x0069]),
  (0xFF4A, [0x006A]),
  (0xFF4B, [0x006B]),
  (0xFF4C, [0x006C]),
  (0xFF4D, [0x006D]),
  (0xFF4E, [0x006E]),
  (0xFF4F, [0x006F]),
  (0xFF50, [0x0070]),
  (0xFF51, [0x0071]),
  (0xFF52, [0x0072]),
  (0xFF53, [0x0073]),
  (0xFF54, [0x0074]),
  (0xFF55, [0x0075]),
  (0xFF56, [0x0076]),
  (0xFF57, [0x0077]),
  (0xFF58, [0x0078]),
  (0xFF59, [0x0079]),
  (0xFF5A, [0x007A]),
  (0xFF5B, [0x007B]),
  (0xFF5C, [0x007C]),
  (0xFF5D, [0x007D]),
  (0xFF5E, [0x007E]),
  (0xFF5F, [0x2985]),
  (0xFF60, [0x2986]),
  (0xFF61, [0x3002]),
  (0xFF62, [0x300C]),
  (0xFF63, [0x300D]),
  (0xFF64, [0x3001]),
  (0xFF65, [0x30FB]),
  (0xFF66, [0x30F2]),
  (0xFF67, [0x30A1]),
  (0xFF68, [0x30A3]),
  (0xFF69, [0x30A5]),
  (0xFF6A, [0x30A7]),
  (0xFF6B, [0x30A9]),
  (0xFF6C, [0x30E3]),
  (0xFF6D, [0x30E5]),
  (0xFF6E, [0x30E7]),
  (0xFF6F, [0x30C3]),
  (0xFF70, [0x30FC]),
  (0xFF71, [0x30A2]),
  (0xFF72, [0x30A4]),
  (0xFF73, [0x30A6]),
  (0xFF74, [0x30A8]),
  (0xFF75, [0x30AA]),
  (0xFF76, [0x30AB]),
  (0xFF77, [0x30AD]),
  (0xFF78, [0x30AF]),
  (0xFF79, [0x30B1]),
  (0xFF7A, [0x30B3]),
  (0xFF7B, [0x30B5]),
  (0xFF7C, [0x30B7]),
  (0xFF7D, [0x30B9]),
  (0xFF7E, [0x30BB]),
  (0xFF7F, [0x30BD]),
  (0xFF80, [0x30BF]),
  (0xFF81, [0x30C1]),
  (0xFF82, [0x30C4]),
  (0xFF83, [0x30C6]),
  (0xFF84, [0x30C8]),
  (0xFF85, [0x30CA]),
  (0xFF86, [0x30CB]),
  (0xFF87, [0x30CC]),
  (0xFF88, [0x30CD]),
  (0xFF89, [0x30CE]),
  (0xFF8A, [0x30CF]),
  (0xFF8B, [0x30D2]),
  (0xFF8C, [0x30D5]),
  (0xFF8D, [0x30D8]),
  (0xFF8E, [0x30DB]),
  (0xFF8F, [0x30DE]),
  (0xFF90, [0x30DF]),
  (0xFF91, [0x30E0]),
  (0xFF92, [0x30E1]),
  (0xFF93, [0x30E2]),
  (0xFF94, [0x30E4]),
  (0xFF95, [0x30E6]),
  (0xFF96, [0x30E8]),
  (0xFF97, [0x30E9]),
  (0xFF98, [0x30EA]),
  (0xFF99, [0x30EB]),
  (0xFF9A, [0x30EC]),
  (0xFF9B, [0x30ED]),
  (0xFF9C, [0x30EF]),
  (0xFF9D, [0x30F3]),
  (0xFF9E, [0x3099]),
  (0xFF9F, [0x309A]),
  (0xFFA0, [0x3164]),
  (0xFFA1, [0x3131]),
  (0xFFA2, [0x3132]),
  (0xFFA3, [0x3133]),
  (0xFFA4, [0x3134]),
  (0xFFA5, [0x3135]),
  (0xFFA6, [0x3136]),
  (0xFFA7, [0x3137]),
  (0xFFA8, [0x3138]),
  (0xFFA9, [0x3139]),
  (0xFFAA, [0x313A]),
  (0xFFAB, [0x313B]),
  (0xFFAC, [0x313C]),
  (0xFFAD, [0x313D]),
  (0xFFAE, [0x313E]),
  (0xFFAF, [0x313F]),
  (0xFFB0, [0x3140]),
  (0xFFB1, [0x3141]),
  (0xFFB2, [0x3142]),
  (0xFFB3, [0x3143]),
  (0xFFB4, [0x3144]),
  (0xFFB5, [0x3145]),
  (0xFFB6, [0x3146]),
  (0xFFB7, [0x3147]),
  (0xFFB8, [0x3148]),
  (0xFFB9, [0x3149]),
  (0xFFBA, [0x314A]),
  (0xFFBB, [0x314B]),
  (0xFFBC, [0x314C]),
  (0xFFBD, [0x314D]),
  (0xFFBE, [0x314E]),
  (0xFFC2, [0x314F]),
  (0xFFC3, [0x3150]),
  (0xFFC4, [0x3151]),
  (0xFFC5, [0x3152]),
  (0xFFC6, [0x3153]),
  (0xFFC7, [0x3154]),
  (0xFFCA, [0x3155]),
  (0xFFCB, [0x3156]),
  (0xFFCC, [0x3157]),
  (0xFFCD, [0x3158]),
  (0xFFCE, [0x3159]),
  (0xFFCF, [0x315A]),
  (0xFFD2, [0x315B]),
  (0xFFD3, [0x315C]),
  (0xFFD4, [0x315D]),
  (0xFFD5, [0x315E]),
  (0xFFD6, [0x315F]),
  (0xFFD7, [0x3160]),
  (0xFFDA, [0x3161]),
  (0xFFDB, [0x3162]),
  (0xFFDC, [0x3163]),
  (0xFFE0, [0x00A2]),
  (0xFFE1, [0x00A3]),
  (0xFFE2, [0x00AC]),
  (0xFFE3, [0x00AF]),
  (0xFFE4, [0x00A6]),
  (0xFFE5, [0x00A5]),
  (0xFFE6, [0x20A9]),
  (0xFFE8, [0x2502]),
  (0xFFE9, [0x2190]),
  (0xFFEA, [0x2191]),
  (0xFFEB, [0x2192]),
  (0xFFEC, [0x2193]),
  (0xFFED, [0x25A0]),
  (0xFFEE, [0x25CB])
]

/-- Boolean source predicate for UCD width-compatibility mappings. -/
def isSource (cp : Nat) : Bool :=
  decide (cp = 0x3000) ||
  (decide (0xFF01 ≤ cp) && decide (cp ≤ 0xFFBE)) ||
  (decide (0xFFC2 ≤ cp) && decide (cp ≤ 0xFFC7)) ||
  (decide (0xFFCA ≤ cp) && decide (cp ≤ 0xFFCF)) ||
  (decide (0xFFD2 ≤ cp) && decide (cp ≤ 0xFFD7)) ||
  (decide (0xFFDA ≤ cp) && decide (cp ≤ 0xFFDC)) ||
  (decide (0xFFE0 ≤ cp) && decide (cp ≤ 0xFFE6)) ||
  (decide (0xFFE8 ≤ cp) && decide (cp ≤ 0xFFEE))

/-- Generated lookup result carrying its target-stability proof. -/
structure CertifiedMapping where
  target : List Nat
  nonSource : ∀ cp, cp ∈ target → isSource cp = false

/-- Certified lookup for the UCD width-compatibility mapping table. -/
def lookupCertified? (cp : Nat) : Option CertifiedMapping :=
  if isSource cp then
    if cp = 0x3000 then
      some {
        target := [0x0020],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF01 then
      some {
        target := [0x0021],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF02 then
      some {
        target := [0x0022],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF03 then
      some {
        target := [0x0023],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF04 then
      some {
        target := [0x0024],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF05 then
      some {
        target := [0x0025],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF06 then
      some {
        target := [0x0026],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF07 then
      some {
        target := [0x0027],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF08 then
      some {
        target := [0x0028],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF09 then
      some {
        target := [0x0029],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF0A then
      some {
        target := [0x002A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF0B then
      some {
        target := [0x002B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF0C then
      some {
        target := [0x002C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF0D then
      some {
        target := [0x002D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF0E then
      some {
        target := [0x002E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF0F then
      some {
        target := [0x002F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF10 then
      some {
        target := [0x0030],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF11 then
      some {
        target := [0x0031],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF12 then
      some {
        target := [0x0032],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF13 then
      some {
        target := [0x0033],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF14 then
      some {
        target := [0x0034],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF15 then
      some {
        target := [0x0035],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF16 then
      some {
        target := [0x0036],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF17 then
      some {
        target := [0x0037],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF18 then
      some {
        target := [0x0038],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF19 then
      some {
        target := [0x0039],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF1A then
      some {
        target := [0x003A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF1B then
      some {
        target := [0x003B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF1C then
      some {
        target := [0x003C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF1D then
      some {
        target := [0x003D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF1E then
      some {
        target := [0x003E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF1F then
      some {
        target := [0x003F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF20 then
      some {
        target := [0x0040],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF21 then
      some {
        target := [0x0041],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF22 then
      some {
        target := [0x0042],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF23 then
      some {
        target := [0x0043],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF24 then
      some {
        target := [0x0044],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF25 then
      some {
        target := [0x0045],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF26 then
      some {
        target := [0x0046],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF27 then
      some {
        target := [0x0047],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF28 then
      some {
        target := [0x0048],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF29 then
      some {
        target := [0x0049],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF2A then
      some {
        target := [0x004A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF2B then
      some {
        target := [0x004B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF2C then
      some {
        target := [0x004C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF2D then
      some {
        target := [0x004D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF2E then
      some {
        target := [0x004E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF2F then
      some {
        target := [0x004F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF30 then
      some {
        target := [0x0050],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF31 then
      some {
        target := [0x0051],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF32 then
      some {
        target := [0x0052],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF33 then
      some {
        target := [0x0053],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF34 then
      some {
        target := [0x0054],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF35 then
      some {
        target := [0x0055],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF36 then
      some {
        target := [0x0056],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF37 then
      some {
        target := [0x0057],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF38 then
      some {
        target := [0x0058],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF39 then
      some {
        target := [0x0059],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF3A then
      some {
        target := [0x005A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF3B then
      some {
        target := [0x005B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF3C then
      some {
        target := [0x005C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF3D then
      some {
        target := [0x005D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF3E then
      some {
        target := [0x005E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF3F then
      some {
        target := [0x005F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF40 then
      some {
        target := [0x0060],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF41 then
      some {
        target := [0x0061],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF42 then
      some {
        target := [0x0062],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF43 then
      some {
        target := [0x0063],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF44 then
      some {
        target := [0x0064],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF45 then
      some {
        target := [0x0065],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF46 then
      some {
        target := [0x0066],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF47 then
      some {
        target := [0x0067],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF48 then
      some {
        target := [0x0068],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF49 then
      some {
        target := [0x0069],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF4A then
      some {
        target := [0x006A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF4B then
      some {
        target := [0x006B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF4C then
      some {
        target := [0x006C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF4D then
      some {
        target := [0x006D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF4E then
      some {
        target := [0x006E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF4F then
      some {
        target := [0x006F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF50 then
      some {
        target := [0x0070],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF51 then
      some {
        target := [0x0071],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF52 then
      some {
        target := [0x0072],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF53 then
      some {
        target := [0x0073],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF54 then
      some {
        target := [0x0074],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF55 then
      some {
        target := [0x0075],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF56 then
      some {
        target := [0x0076],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF57 then
      some {
        target := [0x0077],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF58 then
      some {
        target := [0x0078],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF59 then
      some {
        target := [0x0079],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF5A then
      some {
        target := [0x007A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF5B then
      some {
        target := [0x007B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF5C then
      some {
        target := [0x007C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF5D then
      some {
        target := [0x007D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF5E then
      some {
        target := [0x007E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF5F then
      some {
        target := [0x2985],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF60 then
      some {
        target := [0x2986],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF61 then
      some {
        target := [0x3002],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF62 then
      some {
        target := [0x300C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF63 then
      some {
        target := [0x300D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF64 then
      some {
        target := [0x3001],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF65 then
      some {
        target := [0x30FB],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF66 then
      some {
        target := [0x30F2],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF67 then
      some {
        target := [0x30A1],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF68 then
      some {
        target := [0x30A3],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF69 then
      some {
        target := [0x30A5],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF6A then
      some {
        target := [0x30A7],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF6B then
      some {
        target := [0x30A9],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF6C then
      some {
        target := [0x30E3],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF6D then
      some {
        target := [0x30E5],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF6E then
      some {
        target := [0x30E7],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF6F then
      some {
        target := [0x30C3],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF70 then
      some {
        target := [0x30FC],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF71 then
      some {
        target := [0x30A2],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF72 then
      some {
        target := [0x30A4],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF73 then
      some {
        target := [0x30A6],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF74 then
      some {
        target := [0x30A8],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF75 then
      some {
        target := [0x30AA],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF76 then
      some {
        target := [0x30AB],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF77 then
      some {
        target := [0x30AD],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF78 then
      some {
        target := [0x30AF],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF79 then
      some {
        target := [0x30B1],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF7A then
      some {
        target := [0x30B3],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF7B then
      some {
        target := [0x30B5],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF7C then
      some {
        target := [0x30B7],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF7D then
      some {
        target := [0x30B9],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF7E then
      some {
        target := [0x30BB],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF7F then
      some {
        target := [0x30BD],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF80 then
      some {
        target := [0x30BF],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF81 then
      some {
        target := [0x30C1],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF82 then
      some {
        target := [0x30C4],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF83 then
      some {
        target := [0x30C6],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF84 then
      some {
        target := [0x30C8],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF85 then
      some {
        target := [0x30CA],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF86 then
      some {
        target := [0x30CB],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF87 then
      some {
        target := [0x30CC],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF88 then
      some {
        target := [0x30CD],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF89 then
      some {
        target := [0x30CE],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF8A then
      some {
        target := [0x30CF],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF8B then
      some {
        target := [0x30D2],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF8C then
      some {
        target := [0x30D5],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF8D then
      some {
        target := [0x30D8],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF8E then
      some {
        target := [0x30DB],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF8F then
      some {
        target := [0x30DE],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF90 then
      some {
        target := [0x30DF],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF91 then
      some {
        target := [0x30E0],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF92 then
      some {
        target := [0x30E1],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF93 then
      some {
        target := [0x30E2],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF94 then
      some {
        target := [0x30E4],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF95 then
      some {
        target := [0x30E6],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF96 then
      some {
        target := [0x30E8],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF97 then
      some {
        target := [0x30E9],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF98 then
      some {
        target := [0x30EA],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF99 then
      some {
        target := [0x30EB],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF9A then
      some {
        target := [0x30EC],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF9B then
      some {
        target := [0x30ED],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF9C then
      some {
        target := [0x30EF],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF9D then
      some {
        target := [0x30F3],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF9E then
      some {
        target := [0x3099],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFF9F then
      some {
        target := [0x309A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA0 then
      some {
        target := [0x3164],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA1 then
      some {
        target := [0x3131],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA2 then
      some {
        target := [0x3132],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA3 then
      some {
        target := [0x3133],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA4 then
      some {
        target := [0x3134],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA5 then
      some {
        target := [0x3135],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA6 then
      some {
        target := [0x3136],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA7 then
      some {
        target := [0x3137],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA8 then
      some {
        target := [0x3138],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFA9 then
      some {
        target := [0x3139],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFAA then
      some {
        target := [0x313A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFAB then
      some {
        target := [0x313B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFAC then
      some {
        target := [0x313C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFAD then
      some {
        target := [0x313D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFAE then
      some {
        target := [0x313E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFAF then
      some {
        target := [0x313F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB0 then
      some {
        target := [0x3140],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB1 then
      some {
        target := [0x3141],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB2 then
      some {
        target := [0x3142],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB3 then
      some {
        target := [0x3143],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB4 then
      some {
        target := [0x3144],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB5 then
      some {
        target := [0x3145],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB6 then
      some {
        target := [0x3146],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB7 then
      some {
        target := [0x3147],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB8 then
      some {
        target := [0x3148],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFB9 then
      some {
        target := [0x3149],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFBA then
      some {
        target := [0x314A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFBB then
      some {
        target := [0x314B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFBC then
      some {
        target := [0x314C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFBD then
      some {
        target := [0x314D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFBE then
      some {
        target := [0x314E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFC2 then
      some {
        target := [0x314F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFC3 then
      some {
        target := [0x3150],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFC4 then
      some {
        target := [0x3151],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFC5 then
      some {
        target := [0x3152],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFC6 then
      some {
        target := [0x3153],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFC7 then
      some {
        target := [0x3154],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFCA then
      some {
        target := [0x3155],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFCB then
      some {
        target := [0x3156],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFCC then
      some {
        target := [0x3157],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFCD then
      some {
        target := [0x3158],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFCE then
      some {
        target := [0x3159],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFCF then
      some {
        target := [0x315A],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFD2 then
      some {
        target := [0x315B],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFD3 then
      some {
        target := [0x315C],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFD4 then
      some {
        target := [0x315D],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFD5 then
      some {
        target := [0x315E],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFD6 then
      some {
        target := [0x315F],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFD7 then
      some {
        target := [0x3160],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFDA then
      some {
        target := [0x3161],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFDB then
      some {
        target := [0x3162],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFDC then
      some {
        target := [0x3163],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE0 then
      some {
        target := [0x00A2],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE1 then
      some {
        target := [0x00A3],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE2 then
      some {
        target := [0x00AC],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE3 then
      some {
        target := [0x00AF],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE4 then
      some {
        target := [0x00A6],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE5 then
      some {
        target := [0x00A5],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE6 then
      some {
        target := [0x20A9],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE8 then
      some {
        target := [0x2502],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFE9 then
      some {
        target := [0x2190],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFEA then
      some {
        target := [0x2191],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFEB then
      some {
        target := [0x2192],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFEC then
      some {
        target := [0x2193],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFED then
      some {
        target := [0x25A0],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else if cp = 0xFFEE then
      some {
        target := [0x25CB],
        nonSource := by
          intro out hOut
          simp [isSource] at hOut ⊢
          omega
      }
    else
      none
  else
    none

/-- Lookup a source codepoint, dropping the proof payload. -/
def lookup? (cp : Nat) : Option (List Nat) :=
  match lookupCertified? cp with
  | some cert => some cert.target
  | none => none

theorem lookup_none_of_non_source (cp : Nat)
    (h : isSource cp = false) :
    lookup? cp = none := by
  unfold lookup? lookupCertified?
  rw [h]
  rfl

theorem lookup_target_non_source (source : Nat) (target : List Nat) (cp : Nat)
    (hLookup : lookup? source = some target) (hMem : cp ∈ target) :
    isSource cp = false := by
  unfold lookup? at hLookup
  cases hCert : lookupCertified? source with
  | none =>
      rw [hCert] at hLookup
      cases hLookup
  | some cert =>
      rw [hCert] at hLookup
      simp at hLookup
      rw [← hLookup] at hMem
      exact cert.nonSource cp hMem

-- ═══════════════════════════════════════════════════════════════════════════════
-- INTEGRITY GATE — `widthCompatMappings` must equal a fresh parse of the
-- <wide>/<narrow> compatibility decompositions in the pinned UnicodeData.txt.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Raw text of `UnicodeData.txt`, embedded at compile time. -/
def unicodeDataRaw : String := include_str "../Ucd/UnicodeData.txt"

def wHexVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

def wHex (s : String) : Nat := s.foldl (fun acc c => acc * 16 + wHexVal c) 0

def wTrim (s : String) : String := (String.trimAscii s).toString

/-- Parse one UnicodeData row → (source, target) if it is a <wide> or
    <narrow> compatibility decomposition. -/
def wParseRow (line : String) : Option (Nat × List Nat) :=
  let fields := line.splitOn ";"
  if fields.length < 6 then none else
  let decomp := wTrim fields[5]!
  if !(decomp.startsWith "<wide>" || decomp.startsWith "<narrow>") then none
  else
    let chars := decomp.toList
    let closeIdx := chars.findIdx (· == '>')
    let rest := wTrim (String.ofList (chars.drop (closeIdx + 1)))
    let mapping := ((rest.splitOn " ").filterMap (fun tok =>
      let t := wTrim tok
      if t.isEmpty then none else some (wHex t)))
    some (wHex (wTrim fields[0]!), mapping)

/-- Fresh parse of the pinned source, used only by the drift gate. -/
def widthCompatMappingsParsed : List (Nat × List Nat) :=
  ((unicodeDataRaw.splitOn "\n").filterMap wParseRow)

#eval do
  unless widthCompatMappings == widthCompatMappingsParsed do
    throw (IO.userError "WidthCompatMappings drift: table ≠ parsed <wide>/<narrow> of UnicodeData.txt")

end Unicode.Generated.WidthCompatMappings
