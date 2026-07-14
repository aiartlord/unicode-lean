{-|
Module      : Unicode.Generated.UnicodeData
Description : NFC-relevant subset of UCD UnicodeData.txt.

GENERATED FILE — DO NOT EDIT. Re-run
@scripts/generate-unicode-data.sh@ to regenerate.

Haskell port of @Unicode.Generated.UnicodeData@. Same UCD source bytes
(see @data/UCD-VERSION@), same row filter
(rows where @canonicalCombiningClass != 0@ OR
@Decomposition_Mapping@ is a canonical — non-@\<tag\>@-prefixed —
sequence). Compatibility decompositions and Hangul syllables
(handled algorithmically in 'Unicode.Normalization.Hangul') are
absent from the table by construction.
-}
module Unicode.Generated.UnicodeData
  ( UnicodeDataRow (UnicodeDataRow, codepoint, canonicalCombiningClass, canonicalDecomposition)
  , rows
  ) where

import Data.Word (Word8)

-- | One entry of the NFC-relevant subset of UnicodeData.txt. Fields
-- correspond to UCD columns 0, 3, and 5 per UAX #44.
data UnicodeDataRow = UnicodeDataRow
  { codepoint               :: !Int
  , canonicalCombiningClass :: !Word8
  , canonicalDecomposition  :: ![Int]
  }
  deriving stock (Eq, Show)

-- | NFC-relevant rows from UnicodeData.txt. Sorted by codepoint
-- (the source file's natural order).
rows :: [UnicodeDataRow]
rows =
  [ UnicodeDataRow { codepoint = 0x00C0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00C1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00C2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00C3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0303] }
  , UnicodeDataRow { codepoint = 0x00C4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00C5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x030A] }
  , UnicodeDataRow { codepoint = 0x00C7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0043, 0x0327] }
  , UnicodeDataRow { codepoint = 0x00C8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00C9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00CA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00CB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00CC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00CD, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00CE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00CF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00D1, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x0303] }
  , UnicodeDataRow { codepoint = 0x00D2, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00D4, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00D5, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0303] }
  , UnicodeDataRow { codepoint = 0x00D6, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00D9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00DA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00DB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00DD, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00E0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00E1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00E2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00E3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0303] }
  , UnicodeDataRow { codepoint = 0x00E4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00E5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x030A] }
  , UnicodeDataRow { codepoint = 0x00E7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0063, 0x0327] }
  , UnicodeDataRow { codepoint = 0x00E8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00E9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00EA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00EB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00EC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00ED, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00EE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00EF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00F1, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x0303] }
  , UnicodeDataRow { codepoint = 0x00F2, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00F3, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00F4, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00F5, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0303] }
  , UnicodeDataRow { codepoint = 0x00F6, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00F9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0300] }
  , UnicodeDataRow { codepoint = 0x00FA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00FB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0302] }
  , UnicodeDataRow { codepoint = 0x00FC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0308] }
  , UnicodeDataRow { codepoint = 0x00FD, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0301] }
  , UnicodeDataRow { codepoint = 0x00FF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0308] }
  , UnicodeDataRow { codepoint = 0x0100, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0101, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0102, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0103, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0104, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0328] }
  , UnicodeDataRow { codepoint = 0x0105, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0328] }
  , UnicodeDataRow { codepoint = 0x0106, canonicalCombiningClass = 0, canonicalDecomposition = [0x0043, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0107, canonicalCombiningClass = 0, canonicalDecomposition = [0x0063, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0108, canonicalCombiningClass = 0, canonicalDecomposition = [0x0043, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0109, canonicalCombiningClass = 0, canonicalDecomposition = [0x0063, 0x0302] }
  , UnicodeDataRow { codepoint = 0x010A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0043, 0x0307] }
  , UnicodeDataRow { codepoint = 0x010B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0063, 0x0307] }
  , UnicodeDataRow { codepoint = 0x010C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0043, 0x030C] }
  , UnicodeDataRow { codepoint = 0x010D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0063, 0x030C] }
  , UnicodeDataRow { codepoint = 0x010E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0044, 0x030C] }
  , UnicodeDataRow { codepoint = 0x010F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0064, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0112, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0113, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0114, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0115, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0116, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0117, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0118, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0328] }
  , UnicodeDataRow { codepoint = 0x0119, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0328] }
  , UnicodeDataRow { codepoint = 0x011A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x030C] }
  , UnicodeDataRow { codepoint = 0x011B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x030C] }
  , UnicodeDataRow { codepoint = 0x011C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0047, 0x0302] }
  , UnicodeDataRow { codepoint = 0x011D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0067, 0x0302] }
  , UnicodeDataRow { codepoint = 0x011E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0047, 0x0306] }
  , UnicodeDataRow { codepoint = 0x011F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0067, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0120, canonicalCombiningClass = 0, canonicalDecomposition = [0x0047, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0121, canonicalCombiningClass = 0, canonicalDecomposition = [0x0067, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0122, canonicalCombiningClass = 0, canonicalDecomposition = [0x0047, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0123, canonicalCombiningClass = 0, canonicalDecomposition = [0x0067, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0124, canonicalCombiningClass = 0, canonicalDecomposition = [0x0048, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0125, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0128, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0303] }
  , UnicodeDataRow { codepoint = 0x0129, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0303] }
  , UnicodeDataRow { codepoint = 0x012A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0304] }
  , UnicodeDataRow { codepoint = 0x012B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0304] }
  , UnicodeDataRow { codepoint = 0x012C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0306] }
  , UnicodeDataRow { codepoint = 0x012D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0306] }
  , UnicodeDataRow { codepoint = 0x012E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0328] }
  , UnicodeDataRow { codepoint = 0x012F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0328] }
  , UnicodeDataRow { codepoint = 0x0130, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0134, canonicalCombiningClass = 0, canonicalDecomposition = [0x004A, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0135, canonicalCombiningClass = 0, canonicalDecomposition = [0x006A, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0136, canonicalCombiningClass = 0, canonicalDecomposition = [0x004B, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0137, canonicalCombiningClass = 0, canonicalDecomposition = [0x006B, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0139, canonicalCombiningClass = 0, canonicalDecomposition = [0x004C, 0x0301] }
  , UnicodeDataRow { codepoint = 0x013A, canonicalCombiningClass = 0, canonicalDecomposition = [0x006C, 0x0301] }
  , UnicodeDataRow { codepoint = 0x013B, canonicalCombiningClass = 0, canonicalDecomposition = [0x004C, 0x0327] }
  , UnicodeDataRow { codepoint = 0x013C, canonicalCombiningClass = 0, canonicalDecomposition = [0x006C, 0x0327] }
  , UnicodeDataRow { codepoint = 0x013D, canonicalCombiningClass = 0, canonicalDecomposition = [0x004C, 0x030C] }
  , UnicodeDataRow { codepoint = 0x013E, canonicalCombiningClass = 0, canonicalDecomposition = [0x006C, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0143, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0144, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0145, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0146, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0147, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0148, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x030C] }
  , UnicodeDataRow { codepoint = 0x014C, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0304] }
  , UnicodeDataRow { codepoint = 0x014D, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0304] }
  , UnicodeDataRow { codepoint = 0x014E, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0306] }
  , UnicodeDataRow { codepoint = 0x014F, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0150, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x030B] }
  , UnicodeDataRow { codepoint = 0x0151, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x030B] }
  , UnicodeDataRow { codepoint = 0x0154, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0155, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0156, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0157, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0158, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0159, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x030C] }
  , UnicodeDataRow { codepoint = 0x015A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0053, 0x0301] }
  , UnicodeDataRow { codepoint = 0x015B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0073, 0x0301] }
  , UnicodeDataRow { codepoint = 0x015C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0053, 0x0302] }
  , UnicodeDataRow { codepoint = 0x015D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0073, 0x0302] }
  , UnicodeDataRow { codepoint = 0x015E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0053, 0x0327] }
  , UnicodeDataRow { codepoint = 0x015F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0073, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0160, canonicalCombiningClass = 0, canonicalDecomposition = [0x0053, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0161, canonicalCombiningClass = 0, canonicalDecomposition = [0x0073, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0162, canonicalCombiningClass = 0, canonicalDecomposition = [0x0054, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0163, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0164, canonicalCombiningClass = 0, canonicalDecomposition = [0x0054, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0165, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0168, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0303] }
  , UnicodeDataRow { codepoint = 0x0169, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0303] }
  , UnicodeDataRow { codepoint = 0x016A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0304] }
  , UnicodeDataRow { codepoint = 0x016B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0304] }
  , UnicodeDataRow { codepoint = 0x016C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0306] }
  , UnicodeDataRow { codepoint = 0x016D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0306] }
  , UnicodeDataRow { codepoint = 0x016E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x030A] }
  , UnicodeDataRow { codepoint = 0x016F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x030A] }
  , UnicodeDataRow { codepoint = 0x0170, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x030B] }
  , UnicodeDataRow { codepoint = 0x0171, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x030B] }
  , UnicodeDataRow { codepoint = 0x0172, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0328] }
  , UnicodeDataRow { codepoint = 0x0173, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0328] }
  , UnicodeDataRow { codepoint = 0x0174, canonicalCombiningClass = 0, canonicalDecomposition = [0x0057, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0175, canonicalCombiningClass = 0, canonicalDecomposition = [0x0077, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0176, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0177, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0302] }
  , UnicodeDataRow { codepoint = 0x0178, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0308] }
  , UnicodeDataRow { codepoint = 0x0179, canonicalCombiningClass = 0, canonicalDecomposition = [0x005A, 0x0301] }
  , UnicodeDataRow { codepoint = 0x017A, canonicalCombiningClass = 0, canonicalDecomposition = [0x007A, 0x0301] }
  , UnicodeDataRow { codepoint = 0x017B, canonicalCombiningClass = 0, canonicalDecomposition = [0x005A, 0x0307] }
  , UnicodeDataRow { codepoint = 0x017C, canonicalCombiningClass = 0, canonicalDecomposition = [0x007A, 0x0307] }
  , UnicodeDataRow { codepoint = 0x017D, canonicalCombiningClass = 0, canonicalDecomposition = [0x005A, 0x030C] }
  , UnicodeDataRow { codepoint = 0x017E, canonicalCombiningClass = 0, canonicalDecomposition = [0x007A, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01A0, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x031B] }
  , UnicodeDataRow { codepoint = 0x01A1, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x031B] }
  , UnicodeDataRow { codepoint = 0x01AF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x031B] }
  , UnicodeDataRow { codepoint = 0x01B0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x031B] }
  , UnicodeDataRow { codepoint = 0x01CD, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01CE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01CF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01D0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01D1, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01D2, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01D4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01D5, canonicalCombiningClass = 0, canonicalDecomposition = [0x00DC, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01D6, canonicalCombiningClass = 0, canonicalDecomposition = [0x00FC, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01D7, canonicalCombiningClass = 0, canonicalDecomposition = [0x00DC, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01D8, canonicalCombiningClass = 0, canonicalDecomposition = [0x00FC, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01D9, canonicalCombiningClass = 0, canonicalDecomposition = [0x00DC, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01DA, canonicalCombiningClass = 0, canonicalDecomposition = [0x00FC, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01DB, canonicalCombiningClass = 0, canonicalDecomposition = [0x00DC, 0x0300] }
  , UnicodeDataRow { codepoint = 0x01DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x00FC, 0x0300] }
  , UnicodeDataRow { codepoint = 0x01DE, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C4, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01DF, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E4, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01E0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0226, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01E1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0227, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01E2, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C6, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01E3, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E6, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01E6, canonicalCombiningClass = 0, canonicalDecomposition = [0x0047, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01E7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0067, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01E8, canonicalCombiningClass = 0, canonicalDecomposition = [0x004B, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01E9, canonicalCombiningClass = 0, canonicalDecomposition = [0x006B, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01EA, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0328] }
  , UnicodeDataRow { codepoint = 0x01EB, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0328] }
  , UnicodeDataRow { codepoint = 0x01EC, canonicalCombiningClass = 0, canonicalDecomposition = [0x01EA, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01ED, canonicalCombiningClass = 0, canonicalDecomposition = [0x01EB, 0x0304] }
  , UnicodeDataRow { codepoint = 0x01EE, canonicalCombiningClass = 0, canonicalDecomposition = [0x01B7, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01EF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0292, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01F0, canonicalCombiningClass = 0, canonicalDecomposition = [0x006A, 0x030C] }
  , UnicodeDataRow { codepoint = 0x01F4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0047, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01F5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0067, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01F8, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x0300] }
  , UnicodeDataRow { codepoint = 0x01F9, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x0300] }
  , UnicodeDataRow { codepoint = 0x01FA, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C5, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01FB, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E5, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01FC, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C6, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01FD, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E6, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01FE, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D8, 0x0301] }
  , UnicodeDataRow { codepoint = 0x01FF, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F8, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0200, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0201, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0202, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0203, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0204, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0205, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0206, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0207, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0208, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0209, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x030F] }
  , UnicodeDataRow { codepoint = 0x020A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0311] }
  , UnicodeDataRow { codepoint = 0x020B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0311] }
  , UnicodeDataRow { codepoint = 0x020C, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x030F] }
  , UnicodeDataRow { codepoint = 0x020D, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x030F] }
  , UnicodeDataRow { codepoint = 0x020E, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0311] }
  , UnicodeDataRow { codepoint = 0x020F, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0210, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0211, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0212, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0213, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0214, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0215, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0216, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0217, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0311] }
  , UnicodeDataRow { codepoint = 0x0218, canonicalCombiningClass = 0, canonicalDecomposition = [0x0053, 0x0326] }
  , UnicodeDataRow { codepoint = 0x0219, canonicalCombiningClass = 0, canonicalDecomposition = [0x0073, 0x0326] }
  , UnicodeDataRow { codepoint = 0x021A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0054, 0x0326] }
  , UnicodeDataRow { codepoint = 0x021B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x0326] }
  , UnicodeDataRow { codepoint = 0x021E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0048, 0x030C] }
  , UnicodeDataRow { codepoint = 0x021F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x030C] }
  , UnicodeDataRow { codepoint = 0x0226, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0227, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0228, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0327] }
  , UnicodeDataRow { codepoint = 0x0229, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0327] }
  , UnicodeDataRow { codepoint = 0x022A, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D6, 0x0304] }
  , UnicodeDataRow { codepoint = 0x022B, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F6, 0x0304] }
  , UnicodeDataRow { codepoint = 0x022C, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D5, 0x0304] }
  , UnicodeDataRow { codepoint = 0x022D, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F5, 0x0304] }
  , UnicodeDataRow { codepoint = 0x022E, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0307] }
  , UnicodeDataRow { codepoint = 0x022F, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0307] }
  , UnicodeDataRow { codepoint = 0x0230, canonicalCombiningClass = 0, canonicalDecomposition = [0x022E, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0231, canonicalCombiningClass = 0, canonicalDecomposition = [0x022F, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0232, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0233, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0304] }
  , UnicodeDataRow { codepoint = 0x0300, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0301, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0302, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0303, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0304, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0305, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0306, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0307, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0308, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0309, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x030A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x030B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x030C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x030D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x030E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x030F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0310, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0311, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0312, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0313, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0314, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0315, canonicalCombiningClass = 232, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0316, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0317, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0318, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0319, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x031A, canonicalCombiningClass = 232, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x031B, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x031C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x031D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x031E, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x031F, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0320, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0321, canonicalCombiningClass = 202, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0322, canonicalCombiningClass = 202, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0323, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0324, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0325, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0326, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0327, canonicalCombiningClass = 202, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0328, canonicalCombiningClass = 202, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0329, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x032A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x032B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x032C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x032D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x032E, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x032F, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0330, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0331, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0332, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0333, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0334, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0335, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0336, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0337, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0338, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0339, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x033A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x033B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x033C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x033D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x033E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x033F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0340, canonicalCombiningClass = 230, canonicalDecomposition = [0x0300] }
  , UnicodeDataRow { codepoint = 0x0341, canonicalCombiningClass = 230, canonicalDecomposition = [0x0301] }
  , UnicodeDataRow { codepoint = 0x0342, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0343, canonicalCombiningClass = 230, canonicalDecomposition = [0x0313] }
  , UnicodeDataRow { codepoint = 0x0344, canonicalCombiningClass = 230, canonicalDecomposition = [0x0308, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0345, canonicalCombiningClass = 240, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0346, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0347, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0348, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0349, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x034A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x034B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x034C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x034D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x034E, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0350, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0351, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0352, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0353, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0354, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0355, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0356, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0357, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0358, canonicalCombiningClass = 232, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0359, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x035A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x035B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x035C, canonicalCombiningClass = 233, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x035D, canonicalCombiningClass = 234, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x035E, canonicalCombiningClass = 234, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x035F, canonicalCombiningClass = 233, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0360, canonicalCombiningClass = 234, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0361, canonicalCombiningClass = 234, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0362, canonicalCombiningClass = 233, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0363, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0364, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0365, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0366, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0367, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0368, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0369, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x036A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x036B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x036C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x036D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x036E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x036F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0374, canonicalCombiningClass = 0, canonicalDecomposition = [0x02B9] }
  , UnicodeDataRow { codepoint = 0x037E, canonicalCombiningClass = 0, canonicalDecomposition = [0x003B] }
  , UnicodeDataRow { codepoint = 0x0385, canonicalCombiningClass = 0, canonicalDecomposition = [0x00A8, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0386, canonicalCombiningClass = 0, canonicalDecomposition = [0x0391, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0387, canonicalCombiningClass = 0, canonicalDecomposition = [0x00B7] }
  , UnicodeDataRow { codepoint = 0x0388, canonicalCombiningClass = 0, canonicalDecomposition = [0x0395, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0389, canonicalCombiningClass = 0, canonicalDecomposition = [0x0397, 0x0301] }
  , UnicodeDataRow { codepoint = 0x038A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0399, 0x0301] }
  , UnicodeDataRow { codepoint = 0x038C, canonicalCombiningClass = 0, canonicalDecomposition = [0x039F, 0x0301] }
  , UnicodeDataRow { codepoint = 0x038E, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A5, 0x0301] }
  , UnicodeDataRow { codepoint = 0x038F, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A9, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0390, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CA, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03AA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0399, 0x0308] }
  , UnicodeDataRow { codepoint = 0x03AB, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A5, 0x0308] }
  , UnicodeDataRow { codepoint = 0x03AC, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03AD, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B5, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03AE, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B7, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03AF, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03B0, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CB, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03CA, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0308] }
  , UnicodeDataRow { codepoint = 0x03CB, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0308] }
  , UnicodeDataRow { codepoint = 0x03CC, canonicalCombiningClass = 0, canonicalDecomposition = [0x03BF, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03CD, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03CE, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C9, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x03D2, 0x0301] }
  , UnicodeDataRow { codepoint = 0x03D4, canonicalCombiningClass = 0, canonicalDecomposition = [0x03D2, 0x0308] }
  , UnicodeDataRow { codepoint = 0x0400, canonicalCombiningClass = 0, canonicalDecomposition = [0x0415, 0x0300] }
  , UnicodeDataRow { codepoint = 0x0401, canonicalCombiningClass = 0, canonicalDecomposition = [0x0415, 0x0308] }
  , UnicodeDataRow { codepoint = 0x0403, canonicalCombiningClass = 0, canonicalDecomposition = [0x0413, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0407, canonicalCombiningClass = 0, canonicalDecomposition = [0x0406, 0x0308] }
  , UnicodeDataRow { codepoint = 0x040C, canonicalCombiningClass = 0, canonicalDecomposition = [0x041A, 0x0301] }
  , UnicodeDataRow { codepoint = 0x040D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0418, 0x0300] }
  , UnicodeDataRow { codepoint = 0x040E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0423, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0419, canonicalCombiningClass = 0, canonicalDecomposition = [0x0418, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0439, canonicalCombiningClass = 0, canonicalDecomposition = [0x0438, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0450, canonicalCombiningClass = 0, canonicalDecomposition = [0x0435, 0x0300] }
  , UnicodeDataRow { codepoint = 0x0451, canonicalCombiningClass = 0, canonicalDecomposition = [0x0435, 0x0308] }
  , UnicodeDataRow { codepoint = 0x0453, canonicalCombiningClass = 0, canonicalDecomposition = [0x0433, 0x0301] }
  , UnicodeDataRow { codepoint = 0x0457, canonicalCombiningClass = 0, canonicalDecomposition = [0x0456, 0x0308] }
  , UnicodeDataRow { codepoint = 0x045C, canonicalCombiningClass = 0, canonicalDecomposition = [0x043A, 0x0301] }
  , UnicodeDataRow { codepoint = 0x045D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0438, 0x0300] }
  , UnicodeDataRow { codepoint = 0x045E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0443, 0x0306] }
  , UnicodeDataRow { codepoint = 0x0476, canonicalCombiningClass = 0, canonicalDecomposition = [0x0474, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0477, canonicalCombiningClass = 0, canonicalDecomposition = [0x0475, 0x030F] }
  , UnicodeDataRow { codepoint = 0x0483, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0484, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0485, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0486, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0487, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x04C1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0416, 0x0306] }
  , UnicodeDataRow { codepoint = 0x04C2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0436, 0x0306] }
  , UnicodeDataRow { codepoint = 0x04D0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0410, 0x0306] }
  , UnicodeDataRow { codepoint = 0x04D1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0430, 0x0306] }
  , UnicodeDataRow { codepoint = 0x04D2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0410, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0430, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04D6, canonicalCombiningClass = 0, canonicalDecomposition = [0x0415, 0x0306] }
  , UnicodeDataRow { codepoint = 0x04D7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0435, 0x0306] }
  , UnicodeDataRow { codepoint = 0x04DA, canonicalCombiningClass = 0, canonicalDecomposition = [0x04D8, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04DB, canonicalCombiningClass = 0, canonicalDecomposition = [0x04D9, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0416, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04DD, canonicalCombiningClass = 0, canonicalDecomposition = [0x0436, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04DE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0417, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04DF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0437, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04E2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0418, 0x0304] }
  , UnicodeDataRow { codepoint = 0x04E3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0438, 0x0304] }
  , UnicodeDataRow { codepoint = 0x04E4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0418, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04E5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0438, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04E6, canonicalCombiningClass = 0, canonicalDecomposition = [0x041E, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04E7, canonicalCombiningClass = 0, canonicalDecomposition = [0x043E, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04EA, canonicalCombiningClass = 0, canonicalDecomposition = [0x04E8, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04EB, canonicalCombiningClass = 0, canonicalDecomposition = [0x04E9, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04EC, canonicalCombiningClass = 0, canonicalDecomposition = [0x042D, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04ED, canonicalCombiningClass = 0, canonicalDecomposition = [0x044D, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04EE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0423, 0x0304] }
  , UnicodeDataRow { codepoint = 0x04EF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0443, 0x0304] }
  , UnicodeDataRow { codepoint = 0x04F0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0423, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04F1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0443, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04F2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0423, 0x030B] }
  , UnicodeDataRow { codepoint = 0x04F3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0443, 0x030B] }
  , UnicodeDataRow { codepoint = 0x04F4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0427, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04F5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0447, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04F8, canonicalCombiningClass = 0, canonicalDecomposition = [0x042B, 0x0308] }
  , UnicodeDataRow { codepoint = 0x04F9, canonicalCombiningClass = 0, canonicalDecomposition = [0x044B, 0x0308] }
  , UnicodeDataRow { codepoint = 0x0591, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0592, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0593, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0594, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0595, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0596, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0597, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0598, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0599, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x059A, canonicalCombiningClass = 222, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x059B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x059C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x059D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x059E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x059F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A2, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A3, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A4, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A5, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A7, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05A9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05AA, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05AB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05AC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05AD, canonicalCombiningClass = 222, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05AE, canonicalCombiningClass = 228, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05AF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B0, canonicalCombiningClass = 10, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B1, canonicalCombiningClass = 11, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B2, canonicalCombiningClass = 12, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B3, canonicalCombiningClass = 13, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B4, canonicalCombiningClass = 14, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B5, canonicalCombiningClass = 15, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B6, canonicalCombiningClass = 16, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B7, canonicalCombiningClass = 17, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B8, canonicalCombiningClass = 18, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05B9, canonicalCombiningClass = 19, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05BA, canonicalCombiningClass = 19, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05BB, canonicalCombiningClass = 20, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05BC, canonicalCombiningClass = 21, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05BD, canonicalCombiningClass = 22, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05BF, canonicalCombiningClass = 23, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05C1, canonicalCombiningClass = 24, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05C2, canonicalCombiningClass = 25, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05C4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05C5, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x05C7, canonicalCombiningClass = 18, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0610, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0611, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0612, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0613, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0614, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0615, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0616, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0617, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0618, canonicalCombiningClass = 30, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0619, canonicalCombiningClass = 31, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x061A, canonicalCombiningClass = 32, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0622, canonicalCombiningClass = 0, canonicalDecomposition = [0x0627, 0x0653] }
  , UnicodeDataRow { codepoint = 0x0623, canonicalCombiningClass = 0, canonicalDecomposition = [0x0627, 0x0654] }
  , UnicodeDataRow { codepoint = 0x0624, canonicalCombiningClass = 0, canonicalDecomposition = [0x0648, 0x0654] }
  , UnicodeDataRow { codepoint = 0x0625, canonicalCombiningClass = 0, canonicalDecomposition = [0x0627, 0x0655] }
  , UnicodeDataRow { codepoint = 0x0626, canonicalCombiningClass = 0, canonicalDecomposition = [0x064A, 0x0654] }
  , UnicodeDataRow { codepoint = 0x064B, canonicalCombiningClass = 27, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x064C, canonicalCombiningClass = 28, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x064D, canonicalCombiningClass = 29, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x064E, canonicalCombiningClass = 30, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x064F, canonicalCombiningClass = 31, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0650, canonicalCombiningClass = 32, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0651, canonicalCombiningClass = 33, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0652, canonicalCombiningClass = 34, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0653, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0654, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0655, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0656, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0657, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0658, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0659, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x065A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x065B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x065C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x065D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x065E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x065F, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0670, canonicalCombiningClass = 35, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06C0, canonicalCombiningClass = 0, canonicalDecomposition = [0x06D5, 0x0654] }
  , UnicodeDataRow { codepoint = 0x06C2, canonicalCombiningClass = 0, canonicalDecomposition = [0x06C1, 0x0654] }
  , UnicodeDataRow { codepoint = 0x06D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x06D2, 0x0654] }
  , UnicodeDataRow { codepoint = 0x06D6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06D7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06D8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06D9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06DA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06DB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06DC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06DF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06E0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06E1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06E2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06E3, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06E4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06E7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06E8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06EA, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06EB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06EC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x06ED, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0711, canonicalCombiningClass = 36, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0730, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0731, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0732, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0733, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0734, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0735, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0736, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0737, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0738, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0739, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x073A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x073B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x073C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x073D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x073E, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x073F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0740, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0741, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0742, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0743, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0744, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0745, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0746, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0747, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0748, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0749, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x074A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07EB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07EC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07ED, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07EE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07EF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07F0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07F1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07F2, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07F3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x07FD, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0816, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0817, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0818, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0819, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x081B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x081C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x081D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x081E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x081F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0820, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0821, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0822, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0823, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0825, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0826, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0827, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0829, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x082A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x082B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x082C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x082D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0859, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x085A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x085B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0897, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0898, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0899, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x089A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x089B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x089C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x089D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x089E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x089F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08CA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08CB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08CC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08CD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08CE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08CF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D0, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D1, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D2, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D3, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08D9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08DA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08DB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08DC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08DD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08DE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08DF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E3, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08E9, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08EA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08EB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08EC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08ED, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08EE, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08EF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F0, canonicalCombiningClass = 27, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F1, canonicalCombiningClass = 28, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F2, canonicalCombiningClass = 29, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08F9, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08FA, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08FB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08FC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08FD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08FE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x08FF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0929, canonicalCombiningClass = 0, canonicalDecomposition = [0x0928, 0x093C] }
  , UnicodeDataRow { codepoint = 0x0931, canonicalCombiningClass = 0, canonicalDecomposition = [0x0930, 0x093C] }
  , UnicodeDataRow { codepoint = 0x0934, canonicalCombiningClass = 0, canonicalDecomposition = [0x0933, 0x093C] }
  , UnicodeDataRow { codepoint = 0x093C, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x094D, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0951, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0952, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0953, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0954, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0958, canonicalCombiningClass = 0, canonicalDecomposition = [0x0915, 0x093C] }
  , UnicodeDataRow { codepoint = 0x0959, canonicalCombiningClass = 0, canonicalDecomposition = [0x0916, 0x093C] }
  , UnicodeDataRow { codepoint = 0x095A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0917, 0x093C] }
  , UnicodeDataRow { codepoint = 0x095B, canonicalCombiningClass = 0, canonicalDecomposition = [0x091C, 0x093C] }
  , UnicodeDataRow { codepoint = 0x095C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0921, 0x093C] }
  , UnicodeDataRow { codepoint = 0x095D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0922, 0x093C] }
  , UnicodeDataRow { codepoint = 0x095E, canonicalCombiningClass = 0, canonicalDecomposition = [0x092B, 0x093C] }
  , UnicodeDataRow { codepoint = 0x095F, canonicalCombiningClass = 0, canonicalDecomposition = [0x092F, 0x093C] }
  , UnicodeDataRow { codepoint = 0x09BC, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x09CB, canonicalCombiningClass = 0, canonicalDecomposition = [0x09C7, 0x09BE] }
  , UnicodeDataRow { codepoint = 0x09CC, canonicalCombiningClass = 0, canonicalDecomposition = [0x09C7, 0x09D7] }
  , UnicodeDataRow { codepoint = 0x09CD, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x09DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x09A1, 0x09BC] }
  , UnicodeDataRow { codepoint = 0x09DD, canonicalCombiningClass = 0, canonicalDecomposition = [0x09A2, 0x09BC] }
  , UnicodeDataRow { codepoint = 0x09DF, canonicalCombiningClass = 0, canonicalDecomposition = [0x09AF, 0x09BC] }
  , UnicodeDataRow { codepoint = 0x09FE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0A33, canonicalCombiningClass = 0, canonicalDecomposition = [0x0A32, 0x0A3C] }
  , UnicodeDataRow { codepoint = 0x0A36, canonicalCombiningClass = 0, canonicalDecomposition = [0x0A38, 0x0A3C] }
  , UnicodeDataRow { codepoint = 0x0A3C, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0A4D, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0A59, canonicalCombiningClass = 0, canonicalDecomposition = [0x0A16, 0x0A3C] }
  , UnicodeDataRow { codepoint = 0x0A5A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0A17, 0x0A3C] }
  , UnicodeDataRow { codepoint = 0x0A5B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0A1C, 0x0A3C] }
  , UnicodeDataRow { codepoint = 0x0A5E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0A2B, 0x0A3C] }
  , UnicodeDataRow { codepoint = 0x0ABC, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0ACD, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0B3C, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0B48, canonicalCombiningClass = 0, canonicalDecomposition = [0x0B47, 0x0B56] }
  , UnicodeDataRow { codepoint = 0x0B4B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0B47, 0x0B3E] }
  , UnicodeDataRow { codepoint = 0x0B4C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0B47, 0x0B57] }
  , UnicodeDataRow { codepoint = 0x0B4D, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0B5C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0B21, 0x0B3C] }
  , UnicodeDataRow { codepoint = 0x0B5D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0B22, 0x0B3C] }
  , UnicodeDataRow { codepoint = 0x0B94, canonicalCombiningClass = 0, canonicalDecomposition = [0x0B92, 0x0BD7] }
  , UnicodeDataRow { codepoint = 0x0BCA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0BC6, 0x0BBE] }
  , UnicodeDataRow { codepoint = 0x0BCB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0BC7, 0x0BBE] }
  , UnicodeDataRow { codepoint = 0x0BCC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0BC6, 0x0BD7] }
  , UnicodeDataRow { codepoint = 0x0BCD, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0C3C, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0C48, canonicalCombiningClass = 0, canonicalDecomposition = [0x0C46, 0x0C56] }
  , UnicodeDataRow { codepoint = 0x0C4D, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0C55, canonicalCombiningClass = 84, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0C56, canonicalCombiningClass = 91, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0CBC, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0CC0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0CBF, 0x0CD5] }
  , UnicodeDataRow { codepoint = 0x0CC7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0CC6, 0x0CD5] }
  , UnicodeDataRow { codepoint = 0x0CC8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0CC6, 0x0CD6] }
  , UnicodeDataRow { codepoint = 0x0CCA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0CC6, 0x0CC2] }
  , UnicodeDataRow { codepoint = 0x0CCB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0CCA, 0x0CD5] }
  , UnicodeDataRow { codepoint = 0x0CCD, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0D3B, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0D3C, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0D4A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0D46, 0x0D3E] }
  , UnicodeDataRow { codepoint = 0x0D4B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0D47, 0x0D3E] }
  , UnicodeDataRow { codepoint = 0x0D4C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0D46, 0x0D57] }
  , UnicodeDataRow { codepoint = 0x0D4D, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0DCA, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0DDA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0DD9, 0x0DCA] }
  , UnicodeDataRow { codepoint = 0x0DDC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0DD9, 0x0DCF] }
  , UnicodeDataRow { codepoint = 0x0DDD, canonicalCombiningClass = 0, canonicalDecomposition = [0x0DDC, 0x0DCA] }
  , UnicodeDataRow { codepoint = 0x0DDE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0DD9, 0x0DDF] }
  , UnicodeDataRow { codepoint = 0x0E38, canonicalCombiningClass = 103, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0E39, canonicalCombiningClass = 103, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0E3A, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0E48, canonicalCombiningClass = 107, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0E49, canonicalCombiningClass = 107, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0E4A, canonicalCombiningClass = 107, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0E4B, canonicalCombiningClass = 107, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0EB8, canonicalCombiningClass = 118, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0EB9, canonicalCombiningClass = 118, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0EBA, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0EC8, canonicalCombiningClass = 122, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0EC9, canonicalCombiningClass = 122, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0ECA, canonicalCombiningClass = 122, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0ECB, canonicalCombiningClass = 122, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F18, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F19, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F35, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F37, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F39, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F43, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F42, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0F4D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F4C, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0F52, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F51, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0F57, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F56, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0F5C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F5B, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0F69, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F40, 0x0FB5] }
  , UnicodeDataRow { codepoint = 0x0F71, canonicalCombiningClass = 129, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F72, canonicalCombiningClass = 130, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F73, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F71, 0x0F72] }
  , UnicodeDataRow { codepoint = 0x0F74, canonicalCombiningClass = 132, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F75, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F71, 0x0F74] }
  , UnicodeDataRow { codepoint = 0x0F76, canonicalCombiningClass = 0, canonicalDecomposition = [0x0FB2, 0x0F80] }
  , UnicodeDataRow { codepoint = 0x0F78, canonicalCombiningClass = 0, canonicalDecomposition = [0x0FB3, 0x0F80] }
  , UnicodeDataRow { codepoint = 0x0F7A, canonicalCombiningClass = 130, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F7B, canonicalCombiningClass = 130, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F7C, canonicalCombiningClass = 130, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F7D, canonicalCombiningClass = 130, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F80, canonicalCombiningClass = 130, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F81, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F71, 0x0F80] }
  , UnicodeDataRow { codepoint = 0x0F82, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F83, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F84, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F86, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F87, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x0F93, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F92, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0F9D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F9C, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0FA2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0FA1, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0FA7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0FA6, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0FAC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0FAB, 0x0FB7] }
  , UnicodeDataRow { codepoint = 0x0FB9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0F90, 0x0FB5] }
  , UnicodeDataRow { codepoint = 0x0FC6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1026, canonicalCombiningClass = 0, canonicalDecomposition = [0x1025, 0x102E] }
  , UnicodeDataRow { codepoint = 0x1037, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1039, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x103A, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x108D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x135D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x135E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x135F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1714, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1715, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1734, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x17D2, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x17DD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x18A9, canonicalCombiningClass = 228, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1939, canonicalCombiningClass = 222, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x193A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x193B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A17, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A18, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A60, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A75, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A76, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A77, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A78, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A79, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A7A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A7B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A7C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1A7F, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB5, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB7, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB8, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AB9, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ABA, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ABB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ABC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ABD, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ABF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC0, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC3, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC4, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AC9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ACA, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ACB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ACC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ACD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ACE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ACF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AD9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ADA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ADB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ADC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1ADD, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AE9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AEA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1AEB, canonicalCombiningClass = 234, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B06, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B05, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B08, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B07, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B0A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B09, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B0C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B0B, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B0E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B0D, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B12, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B11, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B34, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B3B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B3A, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B3D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B3C, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B40, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B3E, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B41, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B3F, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B43, canonicalCombiningClass = 0, canonicalDecomposition = [0x1B42, 0x1B35] }
  , UnicodeDataRow { codepoint = 0x1B44, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B6B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B6C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B6D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B6E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B6F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B70, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B71, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B72, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1B73, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1BAA, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1BAB, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1BE6, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1BF2, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1BF3, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1C37, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD4, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD5, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD7, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD8, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CD9, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CDA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CDB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CDC, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CDD, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CDE, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CDF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE2, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE3, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE4, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE5, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE6, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE7, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CE8, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CED, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CF4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CF8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1CF9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC2, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DC9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DCA, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DCB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DCC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DCD, canonicalCombiningClass = 234, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DCE, canonicalCombiningClass = 214, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DCF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD0, canonicalCombiningClass = 202, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DD9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DDA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DDB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DDC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DDD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DDE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DDF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DE9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DEA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DEB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DEC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DED, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DEE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DEF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF6, canonicalCombiningClass = 232, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF7, canonicalCombiningClass = 228, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF8, canonicalCombiningClass = 228, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DF9, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DFA, canonicalCombiningClass = 218, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DFB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DFC, canonicalCombiningClass = 233, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DFD, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DFE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1DFF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E00, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0325] }
  , UnicodeDataRow { codepoint = 0x1E01, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0325] }
  , UnicodeDataRow { codepoint = 0x1E02, canonicalCombiningClass = 0, canonicalDecomposition = [0x0042, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E03, canonicalCombiningClass = 0, canonicalDecomposition = [0x0062, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E04, canonicalCombiningClass = 0, canonicalDecomposition = [0x0042, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E05, canonicalCombiningClass = 0, canonicalDecomposition = [0x0062, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E06, canonicalCombiningClass = 0, canonicalDecomposition = [0x0042, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E07, canonicalCombiningClass = 0, canonicalDecomposition = [0x0062, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E08, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C7, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E09, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E7, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E0A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0044, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E0B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0064, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E0C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0044, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E0D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0064, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E0E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0044, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E0F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0064, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E10, canonicalCombiningClass = 0, canonicalDecomposition = [0x0044, 0x0327] }
  , UnicodeDataRow { codepoint = 0x1E11, canonicalCombiningClass = 0, canonicalDecomposition = [0x0064, 0x0327] }
  , UnicodeDataRow { codepoint = 0x1E12, canonicalCombiningClass = 0, canonicalDecomposition = [0x0044, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E13, canonicalCombiningClass = 0, canonicalDecomposition = [0x0064, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E14, canonicalCombiningClass = 0, canonicalDecomposition = [0x0112, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1E15, canonicalCombiningClass = 0, canonicalDecomposition = [0x0113, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1E16, canonicalCombiningClass = 0, canonicalDecomposition = [0x0112, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E17, canonicalCombiningClass = 0, canonicalDecomposition = [0x0113, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E18, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E19, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E1A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0330] }
  , UnicodeDataRow { codepoint = 0x1E1B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0330] }
  , UnicodeDataRow { codepoint = 0x1E1C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0228, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1E1D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0229, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1E1E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0046, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E1F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0066, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E20, canonicalCombiningClass = 0, canonicalDecomposition = [0x0047, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1E21, canonicalCombiningClass = 0, canonicalDecomposition = [0x0067, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1E22, canonicalCombiningClass = 0, canonicalDecomposition = [0x0048, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E23, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E24, canonicalCombiningClass = 0, canonicalDecomposition = [0x0048, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E25, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E26, canonicalCombiningClass = 0, canonicalDecomposition = [0x0048, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E27, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E28, canonicalCombiningClass = 0, canonicalDecomposition = [0x0048, 0x0327] }
  , UnicodeDataRow { codepoint = 0x1E29, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x0327] }
  , UnicodeDataRow { codepoint = 0x1E2A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0048, 0x032E] }
  , UnicodeDataRow { codepoint = 0x1E2B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x032E] }
  , UnicodeDataRow { codepoint = 0x1E2C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0330] }
  , UnicodeDataRow { codepoint = 0x1E2D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0330] }
  , UnicodeDataRow { codepoint = 0x1E2E, canonicalCombiningClass = 0, canonicalDecomposition = [0x00CF, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E2F, canonicalCombiningClass = 0, canonicalDecomposition = [0x00EF, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E30, canonicalCombiningClass = 0, canonicalDecomposition = [0x004B, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E31, canonicalCombiningClass = 0, canonicalDecomposition = [0x006B, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E32, canonicalCombiningClass = 0, canonicalDecomposition = [0x004B, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E33, canonicalCombiningClass = 0, canonicalDecomposition = [0x006B, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E34, canonicalCombiningClass = 0, canonicalDecomposition = [0x004B, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E35, canonicalCombiningClass = 0, canonicalDecomposition = [0x006B, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E36, canonicalCombiningClass = 0, canonicalDecomposition = [0x004C, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E37, canonicalCombiningClass = 0, canonicalDecomposition = [0x006C, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E38, canonicalCombiningClass = 0, canonicalDecomposition = [0x1E36, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1E39, canonicalCombiningClass = 0, canonicalDecomposition = [0x1E37, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1E3A, canonicalCombiningClass = 0, canonicalDecomposition = [0x004C, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E3B, canonicalCombiningClass = 0, canonicalDecomposition = [0x006C, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E3C, canonicalCombiningClass = 0, canonicalDecomposition = [0x004C, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E3D, canonicalCombiningClass = 0, canonicalDecomposition = [0x006C, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E3E, canonicalCombiningClass = 0, canonicalDecomposition = [0x004D, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E3F, canonicalCombiningClass = 0, canonicalDecomposition = [0x006D, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E40, canonicalCombiningClass = 0, canonicalDecomposition = [0x004D, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E41, canonicalCombiningClass = 0, canonicalDecomposition = [0x006D, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E42, canonicalCombiningClass = 0, canonicalDecomposition = [0x004D, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E43, canonicalCombiningClass = 0, canonicalDecomposition = [0x006D, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E44, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E45, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E46, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E47, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E48, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E49, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E4A, canonicalCombiningClass = 0, canonicalDecomposition = [0x004E, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E4B, canonicalCombiningClass = 0, canonicalDecomposition = [0x006E, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E4C, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D5, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E4D, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F5, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E4E, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D5, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E4F, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F5, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E50, canonicalCombiningClass = 0, canonicalDecomposition = [0x014C, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1E51, canonicalCombiningClass = 0, canonicalDecomposition = [0x014D, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1E52, canonicalCombiningClass = 0, canonicalDecomposition = [0x014C, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E53, canonicalCombiningClass = 0, canonicalDecomposition = [0x014D, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E54, canonicalCombiningClass = 0, canonicalDecomposition = [0x0050, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E55, canonicalCombiningClass = 0, canonicalDecomposition = [0x0070, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E56, canonicalCombiningClass = 0, canonicalDecomposition = [0x0050, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E57, canonicalCombiningClass = 0, canonicalDecomposition = [0x0070, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E58, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E59, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E5A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E5B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E5C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1E5A, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1E5D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1E5B, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1E5E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0052, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E5F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0072, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E60, canonicalCombiningClass = 0, canonicalDecomposition = [0x0053, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E61, canonicalCombiningClass = 0, canonicalDecomposition = [0x0073, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E62, canonicalCombiningClass = 0, canonicalDecomposition = [0x0053, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E63, canonicalCombiningClass = 0, canonicalDecomposition = [0x0073, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E64, canonicalCombiningClass = 0, canonicalDecomposition = [0x015A, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E65, canonicalCombiningClass = 0, canonicalDecomposition = [0x015B, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E66, canonicalCombiningClass = 0, canonicalDecomposition = [0x0160, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E67, canonicalCombiningClass = 0, canonicalDecomposition = [0x0161, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E68, canonicalCombiningClass = 0, canonicalDecomposition = [0x1E62, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E69, canonicalCombiningClass = 0, canonicalDecomposition = [0x1E63, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E6A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0054, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E6B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E6C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0054, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E6D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E6E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0054, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E6F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E70, canonicalCombiningClass = 0, canonicalDecomposition = [0x0054, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E71, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E72, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0324] }
  , UnicodeDataRow { codepoint = 0x1E73, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0324] }
  , UnicodeDataRow { codepoint = 0x1E74, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0330] }
  , UnicodeDataRow { codepoint = 0x1E75, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0330] }
  , UnicodeDataRow { codepoint = 0x1E76, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E77, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x032D] }
  , UnicodeDataRow { codepoint = 0x1E78, canonicalCombiningClass = 0, canonicalDecomposition = [0x0168, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E79, canonicalCombiningClass = 0, canonicalDecomposition = [0x0169, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E7A, canonicalCombiningClass = 0, canonicalDecomposition = [0x016A, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E7B, canonicalCombiningClass = 0, canonicalDecomposition = [0x016B, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E7C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0056, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1E7D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0076, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1E7E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0056, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E7F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0076, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E80, canonicalCombiningClass = 0, canonicalDecomposition = [0x0057, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1E81, canonicalCombiningClass = 0, canonicalDecomposition = [0x0077, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1E82, canonicalCombiningClass = 0, canonicalDecomposition = [0x0057, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E83, canonicalCombiningClass = 0, canonicalDecomposition = [0x0077, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1E84, canonicalCombiningClass = 0, canonicalDecomposition = [0x0057, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E85, canonicalCombiningClass = 0, canonicalDecomposition = [0x0077, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E86, canonicalCombiningClass = 0, canonicalDecomposition = [0x0057, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E87, canonicalCombiningClass = 0, canonicalDecomposition = [0x0077, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E88, canonicalCombiningClass = 0, canonicalDecomposition = [0x0057, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E89, canonicalCombiningClass = 0, canonicalDecomposition = [0x0077, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E8A, canonicalCombiningClass = 0, canonicalDecomposition = [0x0058, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E8B, canonicalCombiningClass = 0, canonicalDecomposition = [0x0078, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E8C, canonicalCombiningClass = 0, canonicalDecomposition = [0x0058, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E8D, canonicalCombiningClass = 0, canonicalDecomposition = [0x0078, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E8E, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E8F, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1E90, canonicalCombiningClass = 0, canonicalDecomposition = [0x005A, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1E91, canonicalCombiningClass = 0, canonicalDecomposition = [0x007A, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1E92, canonicalCombiningClass = 0, canonicalDecomposition = [0x005A, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E93, canonicalCombiningClass = 0, canonicalDecomposition = [0x007A, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1E94, canonicalCombiningClass = 0, canonicalDecomposition = [0x005A, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E95, canonicalCombiningClass = 0, canonicalDecomposition = [0x007A, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E96, canonicalCombiningClass = 0, canonicalDecomposition = [0x0068, 0x0331] }
  , UnicodeDataRow { codepoint = 0x1E97, canonicalCombiningClass = 0, canonicalDecomposition = [0x0074, 0x0308] }
  , UnicodeDataRow { codepoint = 0x1E98, canonicalCombiningClass = 0, canonicalDecomposition = [0x0077, 0x030A] }
  , UnicodeDataRow { codepoint = 0x1E99, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x030A] }
  , UnicodeDataRow { codepoint = 0x1E9B, canonicalCombiningClass = 0, canonicalDecomposition = [0x017F, 0x0307] }
  , UnicodeDataRow { codepoint = 0x1EA0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EA1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EA2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0041, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EA3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0061, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EA4, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C2, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EA5, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E2, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EA6, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C2, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EA7, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E2, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EA8, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C2, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EA9, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E2, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EAA, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C2, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EAB, canonicalCombiningClass = 0, canonicalDecomposition = [0x00E2, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EAC, canonicalCombiningClass = 0, canonicalDecomposition = [0x1EA0, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1EAD, canonicalCombiningClass = 0, canonicalDecomposition = [0x1EA1, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1EAE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0102, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EAF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0103, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EB0, canonicalCombiningClass = 0, canonicalDecomposition = [0x0102, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EB1, canonicalCombiningClass = 0, canonicalDecomposition = [0x0103, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EB2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0102, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EB3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0103, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EB4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0102, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EB5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0103, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EB6, canonicalCombiningClass = 0, canonicalDecomposition = [0x1EA0, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1EB7, canonicalCombiningClass = 0, canonicalDecomposition = [0x1EA1, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1EB8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EB9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EBA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EBB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EBC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0045, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EBD, canonicalCombiningClass = 0, canonicalDecomposition = [0x0065, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EBE, canonicalCombiningClass = 0, canonicalDecomposition = [0x00CA, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EBF, canonicalCombiningClass = 0, canonicalDecomposition = [0x00EA, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EC0, canonicalCombiningClass = 0, canonicalDecomposition = [0x00CA, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EC1, canonicalCombiningClass = 0, canonicalDecomposition = [0x00EA, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EC2, canonicalCombiningClass = 0, canonicalDecomposition = [0x00CA, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EC3, canonicalCombiningClass = 0, canonicalDecomposition = [0x00EA, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EC4, canonicalCombiningClass = 0, canonicalDecomposition = [0x00CA, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EC5, canonicalCombiningClass = 0, canonicalDecomposition = [0x00EA, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EC6, canonicalCombiningClass = 0, canonicalDecomposition = [0x1EB8, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1EC7, canonicalCombiningClass = 0, canonicalDecomposition = [0x1EB9, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1EC8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EC9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1ECA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0049, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1ECB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0069, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1ECC, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1ECD, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1ECE, canonicalCombiningClass = 0, canonicalDecomposition = [0x004F, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1ECF, canonicalCombiningClass = 0, canonicalDecomposition = [0x006F, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1ED0, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D4, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1ED1, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F4, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1ED2, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D4, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1ED3, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F4, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1ED4, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D4, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1ED5, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F4, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1ED6, canonicalCombiningClass = 0, canonicalDecomposition = [0x00D4, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1ED7, canonicalCombiningClass = 0, canonicalDecomposition = [0x00F4, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1ED8, canonicalCombiningClass = 0, canonicalDecomposition = [0x1ECC, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1ED9, canonicalCombiningClass = 0, canonicalDecomposition = [0x1ECD, 0x0302] }
  , UnicodeDataRow { codepoint = 0x1EDA, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A0, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EDB, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A1, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EDC, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A0, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EDD, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A1, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EDE, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A0, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EDF, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A1, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EE0, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A0, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EE1, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A1, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EE2, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A0, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EE3, canonicalCombiningClass = 0, canonicalDecomposition = [0x01A1, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EE4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EE5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EE6, canonicalCombiningClass = 0, canonicalDecomposition = [0x0055, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EE7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0075, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EE8, canonicalCombiningClass = 0, canonicalDecomposition = [0x01AF, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EE9, canonicalCombiningClass = 0, canonicalDecomposition = [0x01B0, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1EEA, canonicalCombiningClass = 0, canonicalDecomposition = [0x01AF, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EEB, canonicalCombiningClass = 0, canonicalDecomposition = [0x01B0, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EEC, canonicalCombiningClass = 0, canonicalDecomposition = [0x01AF, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EED, canonicalCombiningClass = 0, canonicalDecomposition = [0x01B0, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EEE, canonicalCombiningClass = 0, canonicalDecomposition = [0x01AF, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EEF, canonicalCombiningClass = 0, canonicalDecomposition = [0x01B0, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EF0, canonicalCombiningClass = 0, canonicalDecomposition = [0x01AF, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EF1, canonicalCombiningClass = 0, canonicalDecomposition = [0x01B0, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EF2, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EF3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1EF4, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EF5, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0323] }
  , UnicodeDataRow { codepoint = 0x1EF6, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EF7, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0309] }
  , UnicodeDataRow { codepoint = 0x1EF8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0059, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1EF9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0079, 0x0303] }
  , UnicodeDataRow { codepoint = 0x1F00, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F01, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F02, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F00, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F03, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F01, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F04, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F00, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F05, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F01, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F06, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F00, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F07, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F01, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F08, canonicalCombiningClass = 0, canonicalDecomposition = [0x0391, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F09, canonicalCombiningClass = 0, canonicalDecomposition = [0x0391, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F0A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F08, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F0B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F09, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F0C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F08, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F0D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F09, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F0E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F08, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F0F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F09, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F10, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B5, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F11, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B5, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F12, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F10, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F13, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F11, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F14, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F10, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F15, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F11, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F18, canonicalCombiningClass = 0, canonicalDecomposition = [0x0395, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F19, canonicalCombiningClass = 0, canonicalDecomposition = [0x0395, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F1A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F18, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F1B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F19, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F1C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F18, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F1D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F19, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F20, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B7, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F21, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B7, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F22, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F20, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F23, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F21, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F24, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F20, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F25, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F21, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F26, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F20, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F27, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F21, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F28, canonicalCombiningClass = 0, canonicalDecomposition = [0x0397, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F29, canonicalCombiningClass = 0, canonicalDecomposition = [0x0397, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F2A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F28, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F2B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F29, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F2C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F28, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F2D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F29, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F2E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F28, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F2F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F29, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F30, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F31, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F32, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F30, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F33, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F31, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F34, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F30, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F35, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F31, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F36, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F30, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F37, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F31, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F38, canonicalCombiningClass = 0, canonicalDecomposition = [0x0399, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F39, canonicalCombiningClass = 0, canonicalDecomposition = [0x0399, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F3A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F38, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F3B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F39, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F3C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F38, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F3D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F39, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F3E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F38, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F3F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F39, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F40, canonicalCombiningClass = 0, canonicalDecomposition = [0x03BF, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F41, canonicalCombiningClass = 0, canonicalDecomposition = [0x03BF, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F42, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F40, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F43, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F41, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F44, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F40, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F45, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F41, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F48, canonicalCombiningClass = 0, canonicalDecomposition = [0x039F, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F49, canonicalCombiningClass = 0, canonicalDecomposition = [0x039F, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F4A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F48, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F4B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F49, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F4C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F48, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F4D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F49, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F50, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F51, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F52, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F50, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F53, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F51, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F54, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F50, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F55, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F51, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F56, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F50, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F57, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F51, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F59, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A5, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F5B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F59, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F5D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F59, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F5F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F59, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F60, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C9, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F61, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C9, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F62, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F60, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F63, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F61, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F64, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F60, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F65, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F61, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F66, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F60, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F67, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F61, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F68, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A9, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1F69, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A9, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1F6A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F68, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F6B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F69, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F6C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F68, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F6D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F69, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1F6E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F68, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F6F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F69, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1F70, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F71, canonicalCombiningClass = 0, canonicalDecomposition = [0x03AC] }
  , UnicodeDataRow { codepoint = 0x1F72, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B5, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F73, canonicalCombiningClass = 0, canonicalDecomposition = [0x03AD] }
  , UnicodeDataRow { codepoint = 0x1F74, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B7, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F75, canonicalCombiningClass = 0, canonicalDecomposition = [0x03AE] }
  , UnicodeDataRow { codepoint = 0x1F76, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F77, canonicalCombiningClass = 0, canonicalDecomposition = [0x03AF] }
  , UnicodeDataRow { codepoint = 0x1F78, canonicalCombiningClass = 0, canonicalDecomposition = [0x03BF, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F79, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CC] }
  , UnicodeDataRow { codepoint = 0x1F7A, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F7B, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CD] }
  , UnicodeDataRow { codepoint = 0x1F7C, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C9, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1F7D, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CE] }
  , UnicodeDataRow { codepoint = 0x1F80, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F00, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F81, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F01, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F82, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F02, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F83, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F03, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F84, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F04, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F85, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F05, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F86, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F06, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F87, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F07, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F88, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F08, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F89, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F09, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F8A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F0A, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F8B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F0B, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F8C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F0C, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F8D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F0D, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F8E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F0E, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F8F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F0F, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F90, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F20, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F91, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F21, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F92, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F22, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F93, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F23, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F94, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F24, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F95, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F25, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F96, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F26, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F97, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F27, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F98, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F28, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F99, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F29, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F9A, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F2A, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F9B, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F2B, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F9C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F2C, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F9D, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F2D, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F9E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F2E, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1F9F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F2F, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA0, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F60, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA1, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F61, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA2, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F62, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA3, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F63, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA4, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F64, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA5, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F65, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA6, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F66, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA7, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F67, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA8, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F68, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FA9, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F69, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FAA, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F6A, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FAB, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F6B, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FAC, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F6C, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FAD, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F6D, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FAE, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F6E, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FAF, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F6F, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FB0, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1FB1, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1FB2, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F70, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FB3, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FB4, canonicalCombiningClass = 0, canonicalDecomposition = [0x03AC, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FB6, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B1, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FB7, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FB6, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FB8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0391, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1FB9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0391, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1FBA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0391, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FBB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0386] }
  , UnicodeDataRow { codepoint = 0x1FBC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0391, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FBE, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9] }
  , UnicodeDataRow { codepoint = 0x1FC1, canonicalCombiningClass = 0, canonicalDecomposition = [0x00A8, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FC2, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F74, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FC3, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B7, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FC4, canonicalCombiningClass = 0, canonicalDecomposition = [0x03AE, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FC6, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B7, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FC7, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FC6, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FC8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0395, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FC9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0388] }
  , UnicodeDataRow { codepoint = 0x1FCA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0397, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FCB, canonicalCombiningClass = 0, canonicalDecomposition = [0x0389] }
  , UnicodeDataRow { codepoint = 0x1FCC, canonicalCombiningClass = 0, canonicalDecomposition = [0x0397, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FCD, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FBF, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FCE, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FBF, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1FCF, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FBF, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FD0, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1FD1, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1FD2, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CA, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FD3, canonicalCombiningClass = 0, canonicalDecomposition = [0x0390] }
  , UnicodeDataRow { codepoint = 0x1FD6, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B9, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FD7, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CA, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FD8, canonicalCombiningClass = 0, canonicalDecomposition = [0x0399, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1FD9, canonicalCombiningClass = 0, canonicalDecomposition = [0x0399, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1FDA, canonicalCombiningClass = 0, canonicalDecomposition = [0x0399, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FDB, canonicalCombiningClass = 0, canonicalDecomposition = [0x038A] }
  , UnicodeDataRow { codepoint = 0x1FDD, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FFE, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FDE, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FFE, 0x0301] }
  , UnicodeDataRow { codepoint = 0x1FDF, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FFE, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FE0, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1FE1, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1FE2, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CB, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FE3, canonicalCombiningClass = 0, canonicalDecomposition = [0x03B0] }
  , UnicodeDataRow { codepoint = 0x1FE4, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C1, 0x0313] }
  , UnicodeDataRow { codepoint = 0x1FE5, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C1, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1FE6, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C5, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FE7, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CB, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FE8, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A5, 0x0306] }
  , UnicodeDataRow { codepoint = 0x1FE9, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A5, 0x0304] }
  , UnicodeDataRow { codepoint = 0x1FEA, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A5, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FEB, canonicalCombiningClass = 0, canonicalDecomposition = [0x038E] }
  , UnicodeDataRow { codepoint = 0x1FEC, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A1, 0x0314] }
  , UnicodeDataRow { codepoint = 0x1FED, canonicalCombiningClass = 0, canonicalDecomposition = [0x00A8, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FEE, canonicalCombiningClass = 0, canonicalDecomposition = [0x0385] }
  , UnicodeDataRow { codepoint = 0x1FEF, canonicalCombiningClass = 0, canonicalDecomposition = [0x0060] }
  , UnicodeDataRow { codepoint = 0x1FF2, canonicalCombiningClass = 0, canonicalDecomposition = [0x1F7C, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FF3, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C9, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FF4, canonicalCombiningClass = 0, canonicalDecomposition = [0x03CE, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FF6, canonicalCombiningClass = 0, canonicalDecomposition = [0x03C9, 0x0342] }
  , UnicodeDataRow { codepoint = 0x1FF7, canonicalCombiningClass = 0, canonicalDecomposition = [0x1FF6, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FF8, canonicalCombiningClass = 0, canonicalDecomposition = [0x039F, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FF9, canonicalCombiningClass = 0, canonicalDecomposition = [0x038C] }
  , UnicodeDataRow { codepoint = 0x1FFA, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A9, 0x0300] }
  , UnicodeDataRow { codepoint = 0x1FFB, canonicalCombiningClass = 0, canonicalDecomposition = [0x038F] }
  , UnicodeDataRow { codepoint = 0x1FFC, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A9, 0x0345] }
  , UnicodeDataRow { codepoint = 0x1FFD, canonicalCombiningClass = 0, canonicalDecomposition = [0x00B4] }
  , UnicodeDataRow { codepoint = 0x2000, canonicalCombiningClass = 0, canonicalDecomposition = [0x2002] }
  , UnicodeDataRow { codepoint = 0x2001, canonicalCombiningClass = 0, canonicalDecomposition = [0x2003] }
  , UnicodeDataRow { codepoint = 0x20D0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D2, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D3, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D8, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20D9, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20DA, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20DB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20DC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20E1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20E5, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20E6, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20E7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20E8, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20E9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20EA, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20EB, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20EC, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20ED, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20EE, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20EF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x20F0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2126, canonicalCombiningClass = 0, canonicalDecomposition = [0x03A9] }
  , UnicodeDataRow { codepoint = 0x212A, canonicalCombiningClass = 0, canonicalDecomposition = [0x004B] }
  , UnicodeDataRow { codepoint = 0x212B, canonicalCombiningClass = 0, canonicalDecomposition = [0x00C5] }
  , UnicodeDataRow { codepoint = 0x219A, canonicalCombiningClass = 0, canonicalDecomposition = [0x2190, 0x0338] }
  , UnicodeDataRow { codepoint = 0x219B, canonicalCombiningClass = 0, canonicalDecomposition = [0x2192, 0x0338] }
  , UnicodeDataRow { codepoint = 0x21AE, canonicalCombiningClass = 0, canonicalDecomposition = [0x2194, 0x0338] }
  , UnicodeDataRow { codepoint = 0x21CD, canonicalCombiningClass = 0, canonicalDecomposition = [0x21D0, 0x0338] }
  , UnicodeDataRow { codepoint = 0x21CE, canonicalCombiningClass = 0, canonicalDecomposition = [0x21D4, 0x0338] }
  , UnicodeDataRow { codepoint = 0x21CF, canonicalCombiningClass = 0, canonicalDecomposition = [0x21D2, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2204, canonicalCombiningClass = 0, canonicalDecomposition = [0x2203, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2209, canonicalCombiningClass = 0, canonicalDecomposition = [0x2208, 0x0338] }
  , UnicodeDataRow { codepoint = 0x220C, canonicalCombiningClass = 0, canonicalDecomposition = [0x220B, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2224, canonicalCombiningClass = 0, canonicalDecomposition = [0x2223, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2226, canonicalCombiningClass = 0, canonicalDecomposition = [0x2225, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2241, canonicalCombiningClass = 0, canonicalDecomposition = [0x223C, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2244, canonicalCombiningClass = 0, canonicalDecomposition = [0x2243, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2247, canonicalCombiningClass = 0, canonicalDecomposition = [0x2245, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2249, canonicalCombiningClass = 0, canonicalDecomposition = [0x2248, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2260, canonicalCombiningClass = 0, canonicalDecomposition = [0x003D, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2262, canonicalCombiningClass = 0, canonicalDecomposition = [0x2261, 0x0338] }
  , UnicodeDataRow { codepoint = 0x226D, canonicalCombiningClass = 0, canonicalDecomposition = [0x224D, 0x0338] }
  , UnicodeDataRow { codepoint = 0x226E, canonicalCombiningClass = 0, canonicalDecomposition = [0x003C, 0x0338] }
  , UnicodeDataRow { codepoint = 0x226F, canonicalCombiningClass = 0, canonicalDecomposition = [0x003E, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2270, canonicalCombiningClass = 0, canonicalDecomposition = [0x2264, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2271, canonicalCombiningClass = 0, canonicalDecomposition = [0x2265, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2274, canonicalCombiningClass = 0, canonicalDecomposition = [0x2272, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2275, canonicalCombiningClass = 0, canonicalDecomposition = [0x2273, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2278, canonicalCombiningClass = 0, canonicalDecomposition = [0x2276, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2279, canonicalCombiningClass = 0, canonicalDecomposition = [0x2277, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2280, canonicalCombiningClass = 0, canonicalDecomposition = [0x227A, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2281, canonicalCombiningClass = 0, canonicalDecomposition = [0x227B, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2284, canonicalCombiningClass = 0, canonicalDecomposition = [0x2282, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2285, canonicalCombiningClass = 0, canonicalDecomposition = [0x2283, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2288, canonicalCombiningClass = 0, canonicalDecomposition = [0x2286, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2289, canonicalCombiningClass = 0, canonicalDecomposition = [0x2287, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22AC, canonicalCombiningClass = 0, canonicalDecomposition = [0x22A2, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22AD, canonicalCombiningClass = 0, canonicalDecomposition = [0x22A8, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22AE, canonicalCombiningClass = 0, canonicalDecomposition = [0x22A9, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22AF, canonicalCombiningClass = 0, canonicalDecomposition = [0x22AB, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22E0, canonicalCombiningClass = 0, canonicalDecomposition = [0x227C, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22E1, canonicalCombiningClass = 0, canonicalDecomposition = [0x227D, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22E2, canonicalCombiningClass = 0, canonicalDecomposition = [0x2291, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22E3, canonicalCombiningClass = 0, canonicalDecomposition = [0x2292, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22EA, canonicalCombiningClass = 0, canonicalDecomposition = [0x22B2, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22EB, canonicalCombiningClass = 0, canonicalDecomposition = [0x22B3, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22EC, canonicalCombiningClass = 0, canonicalDecomposition = [0x22B4, 0x0338] }
  , UnicodeDataRow { codepoint = 0x22ED, canonicalCombiningClass = 0, canonicalDecomposition = [0x22B5, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2329, canonicalCombiningClass = 0, canonicalDecomposition = [0x3008] }
  , UnicodeDataRow { codepoint = 0x232A, canonicalCombiningClass = 0, canonicalDecomposition = [0x3009] }
  , UnicodeDataRow { codepoint = 0x2ADC, canonicalCombiningClass = 0, canonicalDecomposition = [0x2ADD, 0x0338] }
  , UnicodeDataRow { codepoint = 0x2CEF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2CF0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2CF1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2D7F, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DE9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DEA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DEB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DEC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DED, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DEE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DEF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DF9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DFA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DFB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DFC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DFD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DFE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2DFF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x302A, canonicalCombiningClass = 218, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x302B, canonicalCombiningClass = 228, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x302C, canonicalCombiningClass = 232, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x302D, canonicalCombiningClass = 222, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x302E, canonicalCombiningClass = 224, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x302F, canonicalCombiningClass = 224, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x304C, canonicalCombiningClass = 0, canonicalDecomposition = [0x304B, 0x3099] }
  , UnicodeDataRow { codepoint = 0x304E, canonicalCombiningClass = 0, canonicalDecomposition = [0x304D, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3050, canonicalCombiningClass = 0, canonicalDecomposition = [0x304F, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3052, canonicalCombiningClass = 0, canonicalDecomposition = [0x3051, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3054, canonicalCombiningClass = 0, canonicalDecomposition = [0x3053, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3056, canonicalCombiningClass = 0, canonicalDecomposition = [0x3055, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3058, canonicalCombiningClass = 0, canonicalDecomposition = [0x3057, 0x3099] }
  , UnicodeDataRow { codepoint = 0x305A, canonicalCombiningClass = 0, canonicalDecomposition = [0x3059, 0x3099] }
  , UnicodeDataRow { codepoint = 0x305C, canonicalCombiningClass = 0, canonicalDecomposition = [0x305B, 0x3099] }
  , UnicodeDataRow { codepoint = 0x305E, canonicalCombiningClass = 0, canonicalDecomposition = [0x305D, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3060, canonicalCombiningClass = 0, canonicalDecomposition = [0x305F, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3062, canonicalCombiningClass = 0, canonicalDecomposition = [0x3061, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3065, canonicalCombiningClass = 0, canonicalDecomposition = [0x3064, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3067, canonicalCombiningClass = 0, canonicalDecomposition = [0x3066, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3069, canonicalCombiningClass = 0, canonicalDecomposition = [0x3068, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3070, canonicalCombiningClass = 0, canonicalDecomposition = [0x306F, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3071, canonicalCombiningClass = 0, canonicalDecomposition = [0x306F, 0x309A] }
  , UnicodeDataRow { codepoint = 0x3073, canonicalCombiningClass = 0, canonicalDecomposition = [0x3072, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3074, canonicalCombiningClass = 0, canonicalDecomposition = [0x3072, 0x309A] }
  , UnicodeDataRow { codepoint = 0x3076, canonicalCombiningClass = 0, canonicalDecomposition = [0x3075, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3077, canonicalCombiningClass = 0, canonicalDecomposition = [0x3075, 0x309A] }
  , UnicodeDataRow { codepoint = 0x3079, canonicalCombiningClass = 0, canonicalDecomposition = [0x3078, 0x3099] }
  , UnicodeDataRow { codepoint = 0x307A, canonicalCombiningClass = 0, canonicalDecomposition = [0x3078, 0x309A] }
  , UnicodeDataRow { codepoint = 0x307C, canonicalCombiningClass = 0, canonicalDecomposition = [0x307B, 0x3099] }
  , UnicodeDataRow { codepoint = 0x307D, canonicalCombiningClass = 0, canonicalDecomposition = [0x307B, 0x309A] }
  , UnicodeDataRow { codepoint = 0x3094, canonicalCombiningClass = 0, canonicalDecomposition = [0x3046, 0x3099] }
  , UnicodeDataRow { codepoint = 0x3099, canonicalCombiningClass = 8, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x309A, canonicalCombiningClass = 8, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x309E, canonicalCombiningClass = 0, canonicalDecomposition = [0x309D, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30AC, canonicalCombiningClass = 0, canonicalDecomposition = [0x30AB, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30AE, canonicalCombiningClass = 0, canonicalDecomposition = [0x30AD, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30B0, canonicalCombiningClass = 0, canonicalDecomposition = [0x30AF, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30B2, canonicalCombiningClass = 0, canonicalDecomposition = [0x30B1, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30B4, canonicalCombiningClass = 0, canonicalDecomposition = [0x30B3, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30B6, canonicalCombiningClass = 0, canonicalDecomposition = [0x30B5, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30B8, canonicalCombiningClass = 0, canonicalDecomposition = [0x30B7, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30BA, canonicalCombiningClass = 0, canonicalDecomposition = [0x30B9, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30BC, canonicalCombiningClass = 0, canonicalDecomposition = [0x30BB, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30BE, canonicalCombiningClass = 0, canonicalDecomposition = [0x30BD, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30C0, canonicalCombiningClass = 0, canonicalDecomposition = [0x30BF, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30C2, canonicalCombiningClass = 0, canonicalDecomposition = [0x30C1, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30C5, canonicalCombiningClass = 0, canonicalDecomposition = [0x30C4, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30C7, canonicalCombiningClass = 0, canonicalDecomposition = [0x30C6, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30C9, canonicalCombiningClass = 0, canonicalDecomposition = [0x30C8, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30D0, canonicalCombiningClass = 0, canonicalDecomposition = [0x30CF, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30D1, canonicalCombiningClass = 0, canonicalDecomposition = [0x30CF, 0x309A] }
  , UnicodeDataRow { codepoint = 0x30D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x30D2, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30D4, canonicalCombiningClass = 0, canonicalDecomposition = [0x30D2, 0x309A] }
  , UnicodeDataRow { codepoint = 0x30D6, canonicalCombiningClass = 0, canonicalDecomposition = [0x30D5, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30D7, canonicalCombiningClass = 0, canonicalDecomposition = [0x30D5, 0x309A] }
  , UnicodeDataRow { codepoint = 0x30D9, canonicalCombiningClass = 0, canonicalDecomposition = [0x30D8, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30DA, canonicalCombiningClass = 0, canonicalDecomposition = [0x30D8, 0x309A] }
  , UnicodeDataRow { codepoint = 0x30DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x30DB, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30DD, canonicalCombiningClass = 0, canonicalDecomposition = [0x30DB, 0x309A] }
  , UnicodeDataRow { codepoint = 0x30F4, canonicalCombiningClass = 0, canonicalDecomposition = [0x30A6, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30F7, canonicalCombiningClass = 0, canonicalDecomposition = [0x30EF, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30F8, canonicalCombiningClass = 0, canonicalDecomposition = [0x30F0, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30F9, canonicalCombiningClass = 0, canonicalDecomposition = [0x30F1, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30FA, canonicalCombiningClass = 0, canonicalDecomposition = [0x30F2, 0x3099] }
  , UnicodeDataRow { codepoint = 0x30FE, canonicalCombiningClass = 0, canonicalDecomposition = [0x30FD, 0x3099] }
  , UnicodeDataRow { codepoint = 0xA66F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA674, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA675, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA676, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA677, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA678, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA679, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA67A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA67B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA67C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA67D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA69E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA69F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA6F0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA6F1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA806, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA82C, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8C4, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E4, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8E9, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8EA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8EB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8EC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8ED, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8EE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8EF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8F0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA8F1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA92B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA92C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA92D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA953, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA9B3, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xA9C0, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAB0, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAB2, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAB3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAB4, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAB7, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAB8, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAABE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAABF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAC1, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xAAF6, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xABED, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xF900, canonicalCombiningClass = 0, canonicalDecomposition = [0x8C48] }
  , UnicodeDataRow { codepoint = 0xF901, canonicalCombiningClass = 0, canonicalDecomposition = [0x66F4] }
  , UnicodeDataRow { codepoint = 0xF902, canonicalCombiningClass = 0, canonicalDecomposition = [0x8ECA] }
  , UnicodeDataRow { codepoint = 0xF903, canonicalCombiningClass = 0, canonicalDecomposition = [0x8CC8] }
  , UnicodeDataRow { codepoint = 0xF904, canonicalCombiningClass = 0, canonicalDecomposition = [0x6ED1] }
  , UnicodeDataRow { codepoint = 0xF905, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E32] }
  , UnicodeDataRow { codepoint = 0xF906, canonicalCombiningClass = 0, canonicalDecomposition = [0x53E5] }
  , UnicodeDataRow { codepoint = 0xF907, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F9C] }
  , UnicodeDataRow { codepoint = 0xF908, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F9C] }
  , UnicodeDataRow { codepoint = 0xF909, canonicalCombiningClass = 0, canonicalDecomposition = [0x5951] }
  , UnicodeDataRow { codepoint = 0xF90A, canonicalCombiningClass = 0, canonicalDecomposition = [0x91D1] }
  , UnicodeDataRow { codepoint = 0xF90B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5587] }
  , UnicodeDataRow { codepoint = 0xF90C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5948] }
  , UnicodeDataRow { codepoint = 0xF90D, canonicalCombiningClass = 0, canonicalDecomposition = [0x61F6] }
  , UnicodeDataRow { codepoint = 0xF90E, canonicalCombiningClass = 0, canonicalDecomposition = [0x7669] }
  , UnicodeDataRow { codepoint = 0xF90F, canonicalCombiningClass = 0, canonicalDecomposition = [0x7F85] }
  , UnicodeDataRow { codepoint = 0xF910, canonicalCombiningClass = 0, canonicalDecomposition = [0x863F] }
  , UnicodeDataRow { codepoint = 0xF911, canonicalCombiningClass = 0, canonicalDecomposition = [0x87BA] }
  , UnicodeDataRow { codepoint = 0xF912, canonicalCombiningClass = 0, canonicalDecomposition = [0x88F8] }
  , UnicodeDataRow { codepoint = 0xF913, canonicalCombiningClass = 0, canonicalDecomposition = [0x908F] }
  , UnicodeDataRow { codepoint = 0xF914, canonicalCombiningClass = 0, canonicalDecomposition = [0x6A02] }
  , UnicodeDataRow { codepoint = 0xF915, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D1B] }
  , UnicodeDataRow { codepoint = 0xF916, canonicalCombiningClass = 0, canonicalDecomposition = [0x70D9] }
  , UnicodeDataRow { codepoint = 0xF917, canonicalCombiningClass = 0, canonicalDecomposition = [0x73DE] }
  , UnicodeDataRow { codepoint = 0xF918, canonicalCombiningClass = 0, canonicalDecomposition = [0x843D] }
  , UnicodeDataRow { codepoint = 0xF919, canonicalCombiningClass = 0, canonicalDecomposition = [0x916A] }
  , UnicodeDataRow { codepoint = 0xF91A, canonicalCombiningClass = 0, canonicalDecomposition = [0x99F1] }
  , UnicodeDataRow { codepoint = 0xF91B, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E82] }
  , UnicodeDataRow { codepoint = 0xF91C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5375] }
  , UnicodeDataRow { codepoint = 0xF91D, canonicalCombiningClass = 0, canonicalDecomposition = [0x6B04] }
  , UnicodeDataRow { codepoint = 0xF91E, canonicalCombiningClass = 0, canonicalDecomposition = [0x721B] }
  , UnicodeDataRow { codepoint = 0xF91F, canonicalCombiningClass = 0, canonicalDecomposition = [0x862D] }
  , UnicodeDataRow { codepoint = 0xF920, canonicalCombiningClass = 0, canonicalDecomposition = [0x9E1E] }
  , UnicodeDataRow { codepoint = 0xF921, canonicalCombiningClass = 0, canonicalDecomposition = [0x5D50] }
  , UnicodeDataRow { codepoint = 0xF922, canonicalCombiningClass = 0, canonicalDecomposition = [0x6FEB] }
  , UnicodeDataRow { codepoint = 0xF923, canonicalCombiningClass = 0, canonicalDecomposition = [0x85CD] }
  , UnicodeDataRow { codepoint = 0xF924, canonicalCombiningClass = 0, canonicalDecomposition = [0x8964] }
  , UnicodeDataRow { codepoint = 0xF925, canonicalCombiningClass = 0, canonicalDecomposition = [0x62C9] }
  , UnicodeDataRow { codepoint = 0xF926, canonicalCombiningClass = 0, canonicalDecomposition = [0x81D8] }
  , UnicodeDataRow { codepoint = 0xF927, canonicalCombiningClass = 0, canonicalDecomposition = [0x881F] }
  , UnicodeDataRow { codepoint = 0xF928, canonicalCombiningClass = 0, canonicalDecomposition = [0x5ECA] }
  , UnicodeDataRow { codepoint = 0xF929, canonicalCombiningClass = 0, canonicalDecomposition = [0x6717] }
  , UnicodeDataRow { codepoint = 0xF92A, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D6A] }
  , UnicodeDataRow { codepoint = 0xF92B, canonicalCombiningClass = 0, canonicalDecomposition = [0x72FC] }
  , UnicodeDataRow { codepoint = 0xF92C, canonicalCombiningClass = 0, canonicalDecomposition = [0x90CE] }
  , UnicodeDataRow { codepoint = 0xF92D, canonicalCombiningClass = 0, canonicalDecomposition = [0x4F86] }
  , UnicodeDataRow { codepoint = 0xF92E, canonicalCombiningClass = 0, canonicalDecomposition = [0x51B7] }
  , UnicodeDataRow { codepoint = 0xF92F, canonicalCombiningClass = 0, canonicalDecomposition = [0x52DE] }
  , UnicodeDataRow { codepoint = 0xF930, canonicalCombiningClass = 0, canonicalDecomposition = [0x64C4] }
  , UnicodeDataRow { codepoint = 0xF931, canonicalCombiningClass = 0, canonicalDecomposition = [0x6AD3] }
  , UnicodeDataRow { codepoint = 0xF932, canonicalCombiningClass = 0, canonicalDecomposition = [0x7210] }
  , UnicodeDataRow { codepoint = 0xF933, canonicalCombiningClass = 0, canonicalDecomposition = [0x76E7] }
  , UnicodeDataRow { codepoint = 0xF934, canonicalCombiningClass = 0, canonicalDecomposition = [0x8001] }
  , UnicodeDataRow { codepoint = 0xF935, canonicalCombiningClass = 0, canonicalDecomposition = [0x8606] }
  , UnicodeDataRow { codepoint = 0xF936, canonicalCombiningClass = 0, canonicalDecomposition = [0x865C] }
  , UnicodeDataRow { codepoint = 0xF937, canonicalCombiningClass = 0, canonicalDecomposition = [0x8DEF] }
  , UnicodeDataRow { codepoint = 0xF938, canonicalCombiningClass = 0, canonicalDecomposition = [0x9732] }
  , UnicodeDataRow { codepoint = 0xF939, canonicalCombiningClass = 0, canonicalDecomposition = [0x9B6F] }
  , UnicodeDataRow { codepoint = 0xF93A, canonicalCombiningClass = 0, canonicalDecomposition = [0x9DFA] }
  , UnicodeDataRow { codepoint = 0xF93B, canonicalCombiningClass = 0, canonicalDecomposition = [0x788C] }
  , UnicodeDataRow { codepoint = 0xF93C, canonicalCombiningClass = 0, canonicalDecomposition = [0x797F] }
  , UnicodeDataRow { codepoint = 0xF93D, canonicalCombiningClass = 0, canonicalDecomposition = [0x7DA0] }
  , UnicodeDataRow { codepoint = 0xF93E, canonicalCombiningClass = 0, canonicalDecomposition = [0x83C9] }
  , UnicodeDataRow { codepoint = 0xF93F, canonicalCombiningClass = 0, canonicalDecomposition = [0x9304] }
  , UnicodeDataRow { codepoint = 0xF940, canonicalCombiningClass = 0, canonicalDecomposition = [0x9E7F] }
  , UnicodeDataRow { codepoint = 0xF941, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AD6] }
  , UnicodeDataRow { codepoint = 0xF942, canonicalCombiningClass = 0, canonicalDecomposition = [0x58DF] }
  , UnicodeDataRow { codepoint = 0xF943, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F04] }
  , UnicodeDataRow { codepoint = 0xF944, canonicalCombiningClass = 0, canonicalDecomposition = [0x7C60] }
  , UnicodeDataRow { codepoint = 0xF945, canonicalCombiningClass = 0, canonicalDecomposition = [0x807E] }
  , UnicodeDataRow { codepoint = 0xF946, canonicalCombiningClass = 0, canonicalDecomposition = [0x7262] }
  , UnicodeDataRow { codepoint = 0xF947, canonicalCombiningClass = 0, canonicalDecomposition = [0x78CA] }
  , UnicodeDataRow { codepoint = 0xF948, canonicalCombiningClass = 0, canonicalDecomposition = [0x8CC2] }
  , UnicodeDataRow { codepoint = 0xF949, canonicalCombiningClass = 0, canonicalDecomposition = [0x96F7] }
  , UnicodeDataRow { codepoint = 0xF94A, canonicalCombiningClass = 0, canonicalDecomposition = [0x58D8] }
  , UnicodeDataRow { codepoint = 0xF94B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C62] }
  , UnicodeDataRow { codepoint = 0xF94C, canonicalCombiningClass = 0, canonicalDecomposition = [0x6A13] }
  , UnicodeDataRow { codepoint = 0xF94D, canonicalCombiningClass = 0, canonicalDecomposition = [0x6DDA] }
  , UnicodeDataRow { codepoint = 0xF94E, canonicalCombiningClass = 0, canonicalDecomposition = [0x6F0F] }
  , UnicodeDataRow { codepoint = 0xF94F, canonicalCombiningClass = 0, canonicalDecomposition = [0x7D2F] }
  , UnicodeDataRow { codepoint = 0xF950, canonicalCombiningClass = 0, canonicalDecomposition = [0x7E37] }
  , UnicodeDataRow { codepoint = 0xF951, canonicalCombiningClass = 0, canonicalDecomposition = [0x964B] }
  , UnicodeDataRow { codepoint = 0xF952, canonicalCombiningClass = 0, canonicalDecomposition = [0x52D2] }
  , UnicodeDataRow { codepoint = 0xF953, canonicalCombiningClass = 0, canonicalDecomposition = [0x808B] }
  , UnicodeDataRow { codepoint = 0xF954, canonicalCombiningClass = 0, canonicalDecomposition = [0x51DC] }
  , UnicodeDataRow { codepoint = 0xF955, canonicalCombiningClass = 0, canonicalDecomposition = [0x51CC] }
  , UnicodeDataRow { codepoint = 0xF956, canonicalCombiningClass = 0, canonicalDecomposition = [0x7A1C] }
  , UnicodeDataRow { codepoint = 0xF957, canonicalCombiningClass = 0, canonicalDecomposition = [0x7DBE] }
  , UnicodeDataRow { codepoint = 0xF958, canonicalCombiningClass = 0, canonicalDecomposition = [0x83F1] }
  , UnicodeDataRow { codepoint = 0xF959, canonicalCombiningClass = 0, canonicalDecomposition = [0x9675] }
  , UnicodeDataRow { codepoint = 0xF95A, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B80] }
  , UnicodeDataRow { codepoint = 0xF95B, canonicalCombiningClass = 0, canonicalDecomposition = [0x62CF] }
  , UnicodeDataRow { codepoint = 0xF95C, canonicalCombiningClass = 0, canonicalDecomposition = [0x6A02] }
  , UnicodeDataRow { codepoint = 0xF95D, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AFE] }
  , UnicodeDataRow { codepoint = 0xF95E, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E39] }
  , UnicodeDataRow { codepoint = 0xF95F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BE7] }
  , UnicodeDataRow { codepoint = 0xF960, canonicalCombiningClass = 0, canonicalDecomposition = [0x6012] }
  , UnicodeDataRow { codepoint = 0xF961, canonicalCombiningClass = 0, canonicalDecomposition = [0x7387] }
  , UnicodeDataRow { codepoint = 0xF962, canonicalCombiningClass = 0, canonicalDecomposition = [0x7570] }
  , UnicodeDataRow { codepoint = 0xF963, canonicalCombiningClass = 0, canonicalDecomposition = [0x5317] }
  , UnicodeDataRow { codepoint = 0xF964, canonicalCombiningClass = 0, canonicalDecomposition = [0x78FB] }
  , UnicodeDataRow { codepoint = 0xF965, canonicalCombiningClass = 0, canonicalDecomposition = [0x4FBF] }
  , UnicodeDataRow { codepoint = 0xF966, canonicalCombiningClass = 0, canonicalDecomposition = [0x5FA9] }
  , UnicodeDataRow { codepoint = 0xF967, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E0D] }
  , UnicodeDataRow { codepoint = 0xF968, canonicalCombiningClass = 0, canonicalDecomposition = [0x6CCC] }
  , UnicodeDataRow { codepoint = 0xF969, canonicalCombiningClass = 0, canonicalDecomposition = [0x6578] }
  , UnicodeDataRow { codepoint = 0xF96A, canonicalCombiningClass = 0, canonicalDecomposition = [0x7D22] }
  , UnicodeDataRow { codepoint = 0xF96B, canonicalCombiningClass = 0, canonicalDecomposition = [0x53C3] }
  , UnicodeDataRow { codepoint = 0xF96C, canonicalCombiningClass = 0, canonicalDecomposition = [0x585E] }
  , UnicodeDataRow { codepoint = 0xF96D, canonicalCombiningClass = 0, canonicalDecomposition = [0x7701] }
  , UnicodeDataRow { codepoint = 0xF96E, canonicalCombiningClass = 0, canonicalDecomposition = [0x8449] }
  , UnicodeDataRow { codepoint = 0xF96F, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AAA] }
  , UnicodeDataRow { codepoint = 0xF970, canonicalCombiningClass = 0, canonicalDecomposition = [0x6BBA] }
  , UnicodeDataRow { codepoint = 0xF971, canonicalCombiningClass = 0, canonicalDecomposition = [0x8FB0] }
  , UnicodeDataRow { codepoint = 0xF972, canonicalCombiningClass = 0, canonicalDecomposition = [0x6C88] }
  , UnicodeDataRow { codepoint = 0xF973, canonicalCombiningClass = 0, canonicalDecomposition = [0x62FE] }
  , UnicodeDataRow { codepoint = 0xF974, canonicalCombiningClass = 0, canonicalDecomposition = [0x82E5] }
  , UnicodeDataRow { codepoint = 0xF975, canonicalCombiningClass = 0, canonicalDecomposition = [0x63A0] }
  , UnicodeDataRow { codepoint = 0xF976, canonicalCombiningClass = 0, canonicalDecomposition = [0x7565] }
  , UnicodeDataRow { codepoint = 0xF977, canonicalCombiningClass = 0, canonicalDecomposition = [0x4EAE] }
  , UnicodeDataRow { codepoint = 0xF978, canonicalCombiningClass = 0, canonicalDecomposition = [0x5169] }
  , UnicodeDataRow { codepoint = 0xF979, canonicalCombiningClass = 0, canonicalDecomposition = [0x51C9] }
  , UnicodeDataRow { codepoint = 0xF97A, canonicalCombiningClass = 0, canonicalDecomposition = [0x6881] }
  , UnicodeDataRow { codepoint = 0xF97B, canonicalCombiningClass = 0, canonicalDecomposition = [0x7CE7] }
  , UnicodeDataRow { codepoint = 0xF97C, canonicalCombiningClass = 0, canonicalDecomposition = [0x826F] }
  , UnicodeDataRow { codepoint = 0xF97D, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AD2] }
  , UnicodeDataRow { codepoint = 0xF97E, canonicalCombiningClass = 0, canonicalDecomposition = [0x91CF] }
  , UnicodeDataRow { codepoint = 0xF97F, canonicalCombiningClass = 0, canonicalDecomposition = [0x52F5] }
  , UnicodeDataRow { codepoint = 0xF980, canonicalCombiningClass = 0, canonicalDecomposition = [0x5442] }
  , UnicodeDataRow { codepoint = 0xF981, canonicalCombiningClass = 0, canonicalDecomposition = [0x5973] }
  , UnicodeDataRow { codepoint = 0xF982, canonicalCombiningClass = 0, canonicalDecomposition = [0x5EEC] }
  , UnicodeDataRow { codepoint = 0xF983, canonicalCombiningClass = 0, canonicalDecomposition = [0x65C5] }
  , UnicodeDataRow { codepoint = 0xF984, canonicalCombiningClass = 0, canonicalDecomposition = [0x6FFE] }
  , UnicodeDataRow { codepoint = 0xF985, canonicalCombiningClass = 0, canonicalDecomposition = [0x792A] }
  , UnicodeDataRow { codepoint = 0xF986, canonicalCombiningClass = 0, canonicalDecomposition = [0x95AD] }
  , UnicodeDataRow { codepoint = 0xF987, canonicalCombiningClass = 0, canonicalDecomposition = [0x9A6A] }
  , UnicodeDataRow { codepoint = 0xF988, canonicalCombiningClass = 0, canonicalDecomposition = [0x9E97] }
  , UnicodeDataRow { codepoint = 0xF989, canonicalCombiningClass = 0, canonicalDecomposition = [0x9ECE] }
  , UnicodeDataRow { codepoint = 0xF98A, canonicalCombiningClass = 0, canonicalDecomposition = [0x529B] }
  , UnicodeDataRow { codepoint = 0xF98B, canonicalCombiningClass = 0, canonicalDecomposition = [0x66C6] }
  , UnicodeDataRow { codepoint = 0xF98C, canonicalCombiningClass = 0, canonicalDecomposition = [0x6B77] }
  , UnicodeDataRow { codepoint = 0xF98D, canonicalCombiningClass = 0, canonicalDecomposition = [0x8F62] }
  , UnicodeDataRow { codepoint = 0xF98E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5E74] }
  , UnicodeDataRow { codepoint = 0xF98F, canonicalCombiningClass = 0, canonicalDecomposition = [0x6190] }
  , UnicodeDataRow { codepoint = 0xF990, canonicalCombiningClass = 0, canonicalDecomposition = [0x6200] }
  , UnicodeDataRow { codepoint = 0xF991, canonicalCombiningClass = 0, canonicalDecomposition = [0x649A] }
  , UnicodeDataRow { codepoint = 0xF992, canonicalCombiningClass = 0, canonicalDecomposition = [0x6F23] }
  , UnicodeDataRow { codepoint = 0xF993, canonicalCombiningClass = 0, canonicalDecomposition = [0x7149] }
  , UnicodeDataRow { codepoint = 0xF994, canonicalCombiningClass = 0, canonicalDecomposition = [0x7489] }
  , UnicodeDataRow { codepoint = 0xF995, canonicalCombiningClass = 0, canonicalDecomposition = [0x79CA] }
  , UnicodeDataRow { codepoint = 0xF996, canonicalCombiningClass = 0, canonicalDecomposition = [0x7DF4] }
  , UnicodeDataRow { codepoint = 0xF997, canonicalCombiningClass = 0, canonicalDecomposition = [0x806F] }
  , UnicodeDataRow { codepoint = 0xF998, canonicalCombiningClass = 0, canonicalDecomposition = [0x8F26] }
  , UnicodeDataRow { codepoint = 0xF999, canonicalCombiningClass = 0, canonicalDecomposition = [0x84EE] }
  , UnicodeDataRow { codepoint = 0xF99A, canonicalCombiningClass = 0, canonicalDecomposition = [0x9023] }
  , UnicodeDataRow { codepoint = 0xF99B, canonicalCombiningClass = 0, canonicalDecomposition = [0x934A] }
  , UnicodeDataRow { codepoint = 0xF99C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5217] }
  , UnicodeDataRow { codepoint = 0xF99D, canonicalCombiningClass = 0, canonicalDecomposition = [0x52A3] }
  , UnicodeDataRow { codepoint = 0xF99E, canonicalCombiningClass = 0, canonicalDecomposition = [0x54BD] }
  , UnicodeDataRow { codepoint = 0xF99F, canonicalCombiningClass = 0, canonicalDecomposition = [0x70C8] }
  , UnicodeDataRow { codepoint = 0xF9A0, canonicalCombiningClass = 0, canonicalDecomposition = [0x88C2] }
  , UnicodeDataRow { codepoint = 0xF9A1, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AAA] }
  , UnicodeDataRow { codepoint = 0xF9A2, canonicalCombiningClass = 0, canonicalDecomposition = [0x5EC9] }
  , UnicodeDataRow { codepoint = 0xF9A3, canonicalCombiningClass = 0, canonicalDecomposition = [0x5FF5] }
  , UnicodeDataRow { codepoint = 0xF9A4, canonicalCombiningClass = 0, canonicalDecomposition = [0x637B] }
  , UnicodeDataRow { codepoint = 0xF9A5, canonicalCombiningClass = 0, canonicalDecomposition = [0x6BAE] }
  , UnicodeDataRow { codepoint = 0xF9A6, canonicalCombiningClass = 0, canonicalDecomposition = [0x7C3E] }
  , UnicodeDataRow { codepoint = 0xF9A7, canonicalCombiningClass = 0, canonicalDecomposition = [0x7375] }
  , UnicodeDataRow { codepoint = 0xF9A8, canonicalCombiningClass = 0, canonicalDecomposition = [0x4EE4] }
  , UnicodeDataRow { codepoint = 0xF9A9, canonicalCombiningClass = 0, canonicalDecomposition = [0x56F9] }
  , UnicodeDataRow { codepoint = 0xF9AA, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BE7] }
  , UnicodeDataRow { codepoint = 0xF9AB, canonicalCombiningClass = 0, canonicalDecomposition = [0x5DBA] }
  , UnicodeDataRow { codepoint = 0xF9AC, canonicalCombiningClass = 0, canonicalDecomposition = [0x601C] }
  , UnicodeDataRow { codepoint = 0xF9AD, canonicalCombiningClass = 0, canonicalDecomposition = [0x73B2] }
  , UnicodeDataRow { codepoint = 0xF9AE, canonicalCombiningClass = 0, canonicalDecomposition = [0x7469] }
  , UnicodeDataRow { codepoint = 0xF9AF, canonicalCombiningClass = 0, canonicalDecomposition = [0x7F9A] }
  , UnicodeDataRow { codepoint = 0xF9B0, canonicalCombiningClass = 0, canonicalDecomposition = [0x8046] }
  , UnicodeDataRow { codepoint = 0xF9B1, canonicalCombiningClass = 0, canonicalDecomposition = [0x9234] }
  , UnicodeDataRow { codepoint = 0xF9B2, canonicalCombiningClass = 0, canonicalDecomposition = [0x96F6] }
  , UnicodeDataRow { codepoint = 0xF9B3, canonicalCombiningClass = 0, canonicalDecomposition = [0x9748] }
  , UnicodeDataRow { codepoint = 0xF9B4, canonicalCombiningClass = 0, canonicalDecomposition = [0x9818] }
  , UnicodeDataRow { codepoint = 0xF9B5, canonicalCombiningClass = 0, canonicalDecomposition = [0x4F8B] }
  , UnicodeDataRow { codepoint = 0xF9B6, canonicalCombiningClass = 0, canonicalDecomposition = [0x79AE] }
  , UnicodeDataRow { codepoint = 0xF9B7, canonicalCombiningClass = 0, canonicalDecomposition = [0x91B4] }
  , UnicodeDataRow { codepoint = 0xF9B8, canonicalCombiningClass = 0, canonicalDecomposition = [0x96B8] }
  , UnicodeDataRow { codepoint = 0xF9B9, canonicalCombiningClass = 0, canonicalDecomposition = [0x60E1] }
  , UnicodeDataRow { codepoint = 0xF9BA, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E86] }
  , UnicodeDataRow { codepoint = 0xF9BB, canonicalCombiningClass = 0, canonicalDecomposition = [0x50DA] }
  , UnicodeDataRow { codepoint = 0xF9BC, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BEE] }
  , UnicodeDataRow { codepoint = 0xF9BD, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C3F] }
  , UnicodeDataRow { codepoint = 0xF9BE, canonicalCombiningClass = 0, canonicalDecomposition = [0x6599] }
  , UnicodeDataRow { codepoint = 0xF9BF, canonicalCombiningClass = 0, canonicalDecomposition = [0x6A02] }
  , UnicodeDataRow { codepoint = 0xF9C0, canonicalCombiningClass = 0, canonicalDecomposition = [0x71CE] }
  , UnicodeDataRow { codepoint = 0xF9C1, canonicalCombiningClass = 0, canonicalDecomposition = [0x7642] }
  , UnicodeDataRow { codepoint = 0xF9C2, canonicalCombiningClass = 0, canonicalDecomposition = [0x84FC] }
  , UnicodeDataRow { codepoint = 0xF9C3, canonicalCombiningClass = 0, canonicalDecomposition = [0x907C] }
  , UnicodeDataRow { codepoint = 0xF9C4, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F8D] }
  , UnicodeDataRow { codepoint = 0xF9C5, canonicalCombiningClass = 0, canonicalDecomposition = [0x6688] }
  , UnicodeDataRow { codepoint = 0xF9C6, canonicalCombiningClass = 0, canonicalDecomposition = [0x962E] }
  , UnicodeDataRow { codepoint = 0xF9C7, canonicalCombiningClass = 0, canonicalDecomposition = [0x5289] }
  , UnicodeDataRow { codepoint = 0xF9C8, canonicalCombiningClass = 0, canonicalDecomposition = [0x677B] }
  , UnicodeDataRow { codepoint = 0xF9C9, canonicalCombiningClass = 0, canonicalDecomposition = [0x67F3] }
  , UnicodeDataRow { codepoint = 0xF9CA, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D41] }
  , UnicodeDataRow { codepoint = 0xF9CB, canonicalCombiningClass = 0, canonicalDecomposition = [0x6E9C] }
  , UnicodeDataRow { codepoint = 0xF9CC, canonicalCombiningClass = 0, canonicalDecomposition = [0x7409] }
  , UnicodeDataRow { codepoint = 0xF9CD, canonicalCombiningClass = 0, canonicalDecomposition = [0x7559] }
  , UnicodeDataRow { codepoint = 0xF9CE, canonicalCombiningClass = 0, canonicalDecomposition = [0x786B] }
  , UnicodeDataRow { codepoint = 0xF9CF, canonicalCombiningClass = 0, canonicalDecomposition = [0x7D10] }
  , UnicodeDataRow { codepoint = 0xF9D0, canonicalCombiningClass = 0, canonicalDecomposition = [0x985E] }
  , UnicodeDataRow { codepoint = 0xF9D1, canonicalCombiningClass = 0, canonicalDecomposition = [0x516D] }
  , UnicodeDataRow { codepoint = 0xF9D2, canonicalCombiningClass = 0, canonicalDecomposition = [0x622E] }
  , UnicodeDataRow { codepoint = 0xF9D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x9678] }
  , UnicodeDataRow { codepoint = 0xF9D4, canonicalCombiningClass = 0, canonicalDecomposition = [0x502B] }
  , UnicodeDataRow { codepoint = 0xF9D5, canonicalCombiningClass = 0, canonicalDecomposition = [0x5D19] }
  , UnicodeDataRow { codepoint = 0xF9D6, canonicalCombiningClass = 0, canonicalDecomposition = [0x6DEA] }
  , UnicodeDataRow { codepoint = 0xF9D7, canonicalCombiningClass = 0, canonicalDecomposition = [0x8F2A] }
  , UnicodeDataRow { codepoint = 0xF9D8, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F8B] }
  , UnicodeDataRow { codepoint = 0xF9D9, canonicalCombiningClass = 0, canonicalDecomposition = [0x6144] }
  , UnicodeDataRow { codepoint = 0xF9DA, canonicalCombiningClass = 0, canonicalDecomposition = [0x6817] }
  , UnicodeDataRow { codepoint = 0xF9DB, canonicalCombiningClass = 0, canonicalDecomposition = [0x7387] }
  , UnicodeDataRow { codepoint = 0xF9DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x9686] }
  , UnicodeDataRow { codepoint = 0xF9DD, canonicalCombiningClass = 0, canonicalDecomposition = [0x5229] }
  , UnicodeDataRow { codepoint = 0xF9DE, canonicalCombiningClass = 0, canonicalDecomposition = [0x540F] }
  , UnicodeDataRow { codepoint = 0xF9DF, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C65] }
  , UnicodeDataRow { codepoint = 0xF9E0, canonicalCombiningClass = 0, canonicalDecomposition = [0x6613] }
  , UnicodeDataRow { codepoint = 0xF9E1, canonicalCombiningClass = 0, canonicalDecomposition = [0x674E] }
  , UnicodeDataRow { codepoint = 0xF9E2, canonicalCombiningClass = 0, canonicalDecomposition = [0x68A8] }
  , UnicodeDataRow { codepoint = 0xF9E3, canonicalCombiningClass = 0, canonicalDecomposition = [0x6CE5] }
  , UnicodeDataRow { codepoint = 0xF9E4, canonicalCombiningClass = 0, canonicalDecomposition = [0x7406] }
  , UnicodeDataRow { codepoint = 0xF9E5, canonicalCombiningClass = 0, canonicalDecomposition = [0x75E2] }
  , UnicodeDataRow { codepoint = 0xF9E6, canonicalCombiningClass = 0, canonicalDecomposition = [0x7F79] }
  , UnicodeDataRow { codepoint = 0xF9E7, canonicalCombiningClass = 0, canonicalDecomposition = [0x88CF] }
  , UnicodeDataRow { codepoint = 0xF9E8, canonicalCombiningClass = 0, canonicalDecomposition = [0x88E1] }
  , UnicodeDataRow { codepoint = 0xF9E9, canonicalCombiningClass = 0, canonicalDecomposition = [0x91CC] }
  , UnicodeDataRow { codepoint = 0xF9EA, canonicalCombiningClass = 0, canonicalDecomposition = [0x96E2] }
  , UnicodeDataRow { codepoint = 0xF9EB, canonicalCombiningClass = 0, canonicalDecomposition = [0x533F] }
  , UnicodeDataRow { codepoint = 0xF9EC, canonicalCombiningClass = 0, canonicalDecomposition = [0x6EBA] }
  , UnicodeDataRow { codepoint = 0xF9ED, canonicalCombiningClass = 0, canonicalDecomposition = [0x541D] }
  , UnicodeDataRow { codepoint = 0xF9EE, canonicalCombiningClass = 0, canonicalDecomposition = [0x71D0] }
  , UnicodeDataRow { codepoint = 0xF9EF, canonicalCombiningClass = 0, canonicalDecomposition = [0x7498] }
  , UnicodeDataRow { codepoint = 0xF9F0, canonicalCombiningClass = 0, canonicalDecomposition = [0x85FA] }
  , UnicodeDataRow { codepoint = 0xF9F1, canonicalCombiningClass = 0, canonicalDecomposition = [0x96A3] }
  , UnicodeDataRow { codepoint = 0xF9F2, canonicalCombiningClass = 0, canonicalDecomposition = [0x9C57] }
  , UnicodeDataRow { codepoint = 0xF9F3, canonicalCombiningClass = 0, canonicalDecomposition = [0x9E9F] }
  , UnicodeDataRow { codepoint = 0xF9F4, canonicalCombiningClass = 0, canonicalDecomposition = [0x6797] }
  , UnicodeDataRow { codepoint = 0xF9F5, canonicalCombiningClass = 0, canonicalDecomposition = [0x6DCB] }
  , UnicodeDataRow { codepoint = 0xF9F6, canonicalCombiningClass = 0, canonicalDecomposition = [0x81E8] }
  , UnicodeDataRow { codepoint = 0xF9F7, canonicalCombiningClass = 0, canonicalDecomposition = [0x7ACB] }
  , UnicodeDataRow { codepoint = 0xF9F8, canonicalCombiningClass = 0, canonicalDecomposition = [0x7B20] }
  , UnicodeDataRow { codepoint = 0xF9F9, canonicalCombiningClass = 0, canonicalDecomposition = [0x7C92] }
  , UnicodeDataRow { codepoint = 0xF9FA, canonicalCombiningClass = 0, canonicalDecomposition = [0x72C0] }
  , UnicodeDataRow { codepoint = 0xF9FB, canonicalCombiningClass = 0, canonicalDecomposition = [0x7099] }
  , UnicodeDataRow { codepoint = 0xF9FC, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B58] }
  , UnicodeDataRow { codepoint = 0xF9FD, canonicalCombiningClass = 0, canonicalDecomposition = [0x4EC0] }
  , UnicodeDataRow { codepoint = 0xF9FE, canonicalCombiningClass = 0, canonicalDecomposition = [0x8336] }
  , UnicodeDataRow { codepoint = 0xF9FF, canonicalCombiningClass = 0, canonicalDecomposition = [0x523A] }
  , UnicodeDataRow { codepoint = 0xFA00, canonicalCombiningClass = 0, canonicalDecomposition = [0x5207] }
  , UnicodeDataRow { codepoint = 0xFA01, canonicalCombiningClass = 0, canonicalDecomposition = [0x5EA6] }
  , UnicodeDataRow { codepoint = 0xFA02, canonicalCombiningClass = 0, canonicalDecomposition = [0x62D3] }
  , UnicodeDataRow { codepoint = 0xFA03, canonicalCombiningClass = 0, canonicalDecomposition = [0x7CD6] }
  , UnicodeDataRow { codepoint = 0xFA04, canonicalCombiningClass = 0, canonicalDecomposition = [0x5B85] }
  , UnicodeDataRow { codepoint = 0xFA05, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D1E] }
  , UnicodeDataRow { codepoint = 0xFA06, canonicalCombiningClass = 0, canonicalDecomposition = [0x66B4] }
  , UnicodeDataRow { codepoint = 0xFA07, canonicalCombiningClass = 0, canonicalDecomposition = [0x8F3B] }
  , UnicodeDataRow { codepoint = 0xFA08, canonicalCombiningClass = 0, canonicalDecomposition = [0x884C] }
  , UnicodeDataRow { codepoint = 0xFA09, canonicalCombiningClass = 0, canonicalDecomposition = [0x964D] }
  , UnicodeDataRow { codepoint = 0xFA0A, canonicalCombiningClass = 0, canonicalDecomposition = [0x898B] }
  , UnicodeDataRow { codepoint = 0xFA0B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5ED3] }
  , UnicodeDataRow { codepoint = 0xFA0C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5140] }
  , UnicodeDataRow { codepoint = 0xFA0D, canonicalCombiningClass = 0, canonicalDecomposition = [0x55C0] }
  , UnicodeDataRow { codepoint = 0xFA10, canonicalCombiningClass = 0, canonicalDecomposition = [0x585A] }
  , UnicodeDataRow { codepoint = 0xFA12, canonicalCombiningClass = 0, canonicalDecomposition = [0x6674] }
  , UnicodeDataRow { codepoint = 0xFA15, canonicalCombiningClass = 0, canonicalDecomposition = [0x51DE] }
  , UnicodeDataRow { codepoint = 0xFA16, canonicalCombiningClass = 0, canonicalDecomposition = [0x732A] }
  , UnicodeDataRow { codepoint = 0xFA17, canonicalCombiningClass = 0, canonicalDecomposition = [0x76CA] }
  , UnicodeDataRow { codepoint = 0xFA18, canonicalCombiningClass = 0, canonicalDecomposition = [0x793C] }
  , UnicodeDataRow { codepoint = 0xFA19, canonicalCombiningClass = 0, canonicalDecomposition = [0x795E] }
  , UnicodeDataRow { codepoint = 0xFA1A, canonicalCombiningClass = 0, canonicalDecomposition = [0x7965] }
  , UnicodeDataRow { codepoint = 0xFA1B, canonicalCombiningClass = 0, canonicalDecomposition = [0x798F] }
  , UnicodeDataRow { codepoint = 0xFA1C, canonicalCombiningClass = 0, canonicalDecomposition = [0x9756] }
  , UnicodeDataRow { codepoint = 0xFA1D, canonicalCombiningClass = 0, canonicalDecomposition = [0x7CBE] }
  , UnicodeDataRow { codepoint = 0xFA1E, canonicalCombiningClass = 0, canonicalDecomposition = [0x7FBD] }
  , UnicodeDataRow { codepoint = 0xFA20, canonicalCombiningClass = 0, canonicalDecomposition = [0x8612] }
  , UnicodeDataRow { codepoint = 0xFA22, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AF8] }
  , UnicodeDataRow { codepoint = 0xFA25, canonicalCombiningClass = 0, canonicalDecomposition = [0x9038] }
  , UnicodeDataRow { codepoint = 0xFA26, canonicalCombiningClass = 0, canonicalDecomposition = [0x90FD] }
  , UnicodeDataRow { codepoint = 0xFA2A, canonicalCombiningClass = 0, canonicalDecomposition = [0x98EF] }
  , UnicodeDataRow { codepoint = 0xFA2B, canonicalCombiningClass = 0, canonicalDecomposition = [0x98FC] }
  , UnicodeDataRow { codepoint = 0xFA2C, canonicalCombiningClass = 0, canonicalDecomposition = [0x9928] }
  , UnicodeDataRow { codepoint = 0xFA2D, canonicalCombiningClass = 0, canonicalDecomposition = [0x9DB4] }
  , UnicodeDataRow { codepoint = 0xFA2E, canonicalCombiningClass = 0, canonicalDecomposition = [0x90DE] }
  , UnicodeDataRow { codepoint = 0xFA2F, canonicalCombiningClass = 0, canonicalDecomposition = [0x96B7] }
  , UnicodeDataRow { codepoint = 0xFA30, canonicalCombiningClass = 0, canonicalDecomposition = [0x4FAE] }
  , UnicodeDataRow { codepoint = 0xFA31, canonicalCombiningClass = 0, canonicalDecomposition = [0x50E7] }
  , UnicodeDataRow { codepoint = 0xFA32, canonicalCombiningClass = 0, canonicalDecomposition = [0x514D] }
  , UnicodeDataRow { codepoint = 0xFA33, canonicalCombiningClass = 0, canonicalDecomposition = [0x52C9] }
  , UnicodeDataRow { codepoint = 0xFA34, canonicalCombiningClass = 0, canonicalDecomposition = [0x52E4] }
  , UnicodeDataRow { codepoint = 0xFA35, canonicalCombiningClass = 0, canonicalDecomposition = [0x5351] }
  , UnicodeDataRow { codepoint = 0xFA36, canonicalCombiningClass = 0, canonicalDecomposition = [0x559D] }
  , UnicodeDataRow { codepoint = 0xFA37, canonicalCombiningClass = 0, canonicalDecomposition = [0x5606] }
  , UnicodeDataRow { codepoint = 0xFA38, canonicalCombiningClass = 0, canonicalDecomposition = [0x5668] }
  , UnicodeDataRow { codepoint = 0xFA39, canonicalCombiningClass = 0, canonicalDecomposition = [0x5840] }
  , UnicodeDataRow { codepoint = 0xFA3A, canonicalCombiningClass = 0, canonicalDecomposition = [0x58A8] }
  , UnicodeDataRow { codepoint = 0xFA3B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C64] }
  , UnicodeDataRow { codepoint = 0xFA3C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C6E] }
  , UnicodeDataRow { codepoint = 0xFA3D, canonicalCombiningClass = 0, canonicalDecomposition = [0x6094] }
  , UnicodeDataRow { codepoint = 0xFA3E, canonicalCombiningClass = 0, canonicalDecomposition = [0x6168] }
  , UnicodeDataRow { codepoint = 0xFA3F, canonicalCombiningClass = 0, canonicalDecomposition = [0x618E] }
  , UnicodeDataRow { codepoint = 0xFA40, canonicalCombiningClass = 0, canonicalDecomposition = [0x61F2] }
  , UnicodeDataRow { codepoint = 0xFA41, canonicalCombiningClass = 0, canonicalDecomposition = [0x654F] }
  , UnicodeDataRow { codepoint = 0xFA42, canonicalCombiningClass = 0, canonicalDecomposition = [0x65E2] }
  , UnicodeDataRow { codepoint = 0xFA43, canonicalCombiningClass = 0, canonicalDecomposition = [0x6691] }
  , UnicodeDataRow { codepoint = 0xFA44, canonicalCombiningClass = 0, canonicalDecomposition = [0x6885] }
  , UnicodeDataRow { codepoint = 0xFA45, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D77] }
  , UnicodeDataRow { codepoint = 0xFA46, canonicalCombiningClass = 0, canonicalDecomposition = [0x6E1A] }
  , UnicodeDataRow { codepoint = 0xFA47, canonicalCombiningClass = 0, canonicalDecomposition = [0x6F22] }
  , UnicodeDataRow { codepoint = 0xFA48, canonicalCombiningClass = 0, canonicalDecomposition = [0x716E] }
  , UnicodeDataRow { codepoint = 0xFA49, canonicalCombiningClass = 0, canonicalDecomposition = [0x722B] }
  , UnicodeDataRow { codepoint = 0xFA4A, canonicalCombiningClass = 0, canonicalDecomposition = [0x7422] }
  , UnicodeDataRow { codepoint = 0xFA4B, canonicalCombiningClass = 0, canonicalDecomposition = [0x7891] }
  , UnicodeDataRow { codepoint = 0xFA4C, canonicalCombiningClass = 0, canonicalDecomposition = [0x793E] }
  , UnicodeDataRow { codepoint = 0xFA4D, canonicalCombiningClass = 0, canonicalDecomposition = [0x7949] }
  , UnicodeDataRow { codepoint = 0xFA4E, canonicalCombiningClass = 0, canonicalDecomposition = [0x7948] }
  , UnicodeDataRow { codepoint = 0xFA4F, canonicalCombiningClass = 0, canonicalDecomposition = [0x7950] }
  , UnicodeDataRow { codepoint = 0xFA50, canonicalCombiningClass = 0, canonicalDecomposition = [0x7956] }
  , UnicodeDataRow { codepoint = 0xFA51, canonicalCombiningClass = 0, canonicalDecomposition = [0x795D] }
  , UnicodeDataRow { codepoint = 0xFA52, canonicalCombiningClass = 0, canonicalDecomposition = [0x798D] }
  , UnicodeDataRow { codepoint = 0xFA53, canonicalCombiningClass = 0, canonicalDecomposition = [0x798E] }
  , UnicodeDataRow { codepoint = 0xFA54, canonicalCombiningClass = 0, canonicalDecomposition = [0x7A40] }
  , UnicodeDataRow { codepoint = 0xFA55, canonicalCombiningClass = 0, canonicalDecomposition = [0x7A81] }
  , UnicodeDataRow { codepoint = 0xFA56, canonicalCombiningClass = 0, canonicalDecomposition = [0x7BC0] }
  , UnicodeDataRow { codepoint = 0xFA57, canonicalCombiningClass = 0, canonicalDecomposition = [0x7DF4] }
  , UnicodeDataRow { codepoint = 0xFA58, canonicalCombiningClass = 0, canonicalDecomposition = [0x7E09] }
  , UnicodeDataRow { codepoint = 0xFA59, canonicalCombiningClass = 0, canonicalDecomposition = [0x7E41] }
  , UnicodeDataRow { codepoint = 0xFA5A, canonicalCombiningClass = 0, canonicalDecomposition = [0x7F72] }
  , UnicodeDataRow { codepoint = 0xFA5B, canonicalCombiningClass = 0, canonicalDecomposition = [0x8005] }
  , UnicodeDataRow { codepoint = 0xFA5C, canonicalCombiningClass = 0, canonicalDecomposition = [0x81ED] }
  , UnicodeDataRow { codepoint = 0xFA5D, canonicalCombiningClass = 0, canonicalDecomposition = [0x8279] }
  , UnicodeDataRow { codepoint = 0xFA5E, canonicalCombiningClass = 0, canonicalDecomposition = [0x8279] }
  , UnicodeDataRow { codepoint = 0xFA5F, canonicalCombiningClass = 0, canonicalDecomposition = [0x8457] }
  , UnicodeDataRow { codepoint = 0xFA60, canonicalCombiningClass = 0, canonicalDecomposition = [0x8910] }
  , UnicodeDataRow { codepoint = 0xFA61, canonicalCombiningClass = 0, canonicalDecomposition = [0x8996] }
  , UnicodeDataRow { codepoint = 0xFA62, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B01] }
  , UnicodeDataRow { codepoint = 0xFA63, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B39] }
  , UnicodeDataRow { codepoint = 0xFA64, canonicalCombiningClass = 0, canonicalDecomposition = [0x8CD3] }
  , UnicodeDataRow { codepoint = 0xFA65, canonicalCombiningClass = 0, canonicalDecomposition = [0x8D08] }
  , UnicodeDataRow { codepoint = 0xFA66, canonicalCombiningClass = 0, canonicalDecomposition = [0x8FB6] }
  , UnicodeDataRow { codepoint = 0xFA67, canonicalCombiningClass = 0, canonicalDecomposition = [0x9038] }
  , UnicodeDataRow { codepoint = 0xFA68, canonicalCombiningClass = 0, canonicalDecomposition = [0x96E3] }
  , UnicodeDataRow { codepoint = 0xFA69, canonicalCombiningClass = 0, canonicalDecomposition = [0x97FF] }
  , UnicodeDataRow { codepoint = 0xFA6A, canonicalCombiningClass = 0, canonicalDecomposition = [0x983B] }
  , UnicodeDataRow { codepoint = 0xFA6B, canonicalCombiningClass = 0, canonicalDecomposition = [0x6075] }
  , UnicodeDataRow { codepoint = 0xFA6C, canonicalCombiningClass = 0, canonicalDecomposition = [0x242EE] }
  , UnicodeDataRow { codepoint = 0xFA6D, canonicalCombiningClass = 0, canonicalDecomposition = [0x8218] }
  , UnicodeDataRow { codepoint = 0xFA70, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E26] }
  , UnicodeDataRow { codepoint = 0xFA71, canonicalCombiningClass = 0, canonicalDecomposition = [0x51B5] }
  , UnicodeDataRow { codepoint = 0xFA72, canonicalCombiningClass = 0, canonicalDecomposition = [0x5168] }
  , UnicodeDataRow { codepoint = 0xFA73, canonicalCombiningClass = 0, canonicalDecomposition = [0x4F80] }
  , UnicodeDataRow { codepoint = 0xFA74, canonicalCombiningClass = 0, canonicalDecomposition = [0x5145] }
  , UnicodeDataRow { codepoint = 0xFA75, canonicalCombiningClass = 0, canonicalDecomposition = [0x5180] }
  , UnicodeDataRow { codepoint = 0xFA76, canonicalCombiningClass = 0, canonicalDecomposition = [0x52C7] }
  , UnicodeDataRow { codepoint = 0xFA77, canonicalCombiningClass = 0, canonicalDecomposition = [0x52FA] }
  , UnicodeDataRow { codepoint = 0xFA78, canonicalCombiningClass = 0, canonicalDecomposition = [0x559D] }
  , UnicodeDataRow { codepoint = 0xFA79, canonicalCombiningClass = 0, canonicalDecomposition = [0x5555] }
  , UnicodeDataRow { codepoint = 0xFA7A, canonicalCombiningClass = 0, canonicalDecomposition = [0x5599] }
  , UnicodeDataRow { codepoint = 0xFA7B, canonicalCombiningClass = 0, canonicalDecomposition = [0x55E2] }
  , UnicodeDataRow { codepoint = 0xFA7C, canonicalCombiningClass = 0, canonicalDecomposition = [0x585A] }
  , UnicodeDataRow { codepoint = 0xFA7D, canonicalCombiningClass = 0, canonicalDecomposition = [0x58B3] }
  , UnicodeDataRow { codepoint = 0xFA7E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5944] }
  , UnicodeDataRow { codepoint = 0xFA7F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5954] }
  , UnicodeDataRow { codepoint = 0xFA80, canonicalCombiningClass = 0, canonicalDecomposition = [0x5A62] }
  , UnicodeDataRow { codepoint = 0xFA81, canonicalCombiningClass = 0, canonicalDecomposition = [0x5B28] }
  , UnicodeDataRow { codepoint = 0xFA82, canonicalCombiningClass = 0, canonicalDecomposition = [0x5ED2] }
  , UnicodeDataRow { codepoint = 0xFA83, canonicalCombiningClass = 0, canonicalDecomposition = [0x5ED9] }
  , UnicodeDataRow { codepoint = 0xFA84, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F69] }
  , UnicodeDataRow { codepoint = 0xFA85, canonicalCombiningClass = 0, canonicalDecomposition = [0x5FAD] }
  , UnicodeDataRow { codepoint = 0xFA86, canonicalCombiningClass = 0, canonicalDecomposition = [0x60D8] }
  , UnicodeDataRow { codepoint = 0xFA87, canonicalCombiningClass = 0, canonicalDecomposition = [0x614E] }
  , UnicodeDataRow { codepoint = 0xFA88, canonicalCombiningClass = 0, canonicalDecomposition = [0x6108] }
  , UnicodeDataRow { codepoint = 0xFA89, canonicalCombiningClass = 0, canonicalDecomposition = [0x618E] }
  , UnicodeDataRow { codepoint = 0xFA8A, canonicalCombiningClass = 0, canonicalDecomposition = [0x6160] }
  , UnicodeDataRow { codepoint = 0xFA8B, canonicalCombiningClass = 0, canonicalDecomposition = [0x61F2] }
  , UnicodeDataRow { codepoint = 0xFA8C, canonicalCombiningClass = 0, canonicalDecomposition = [0x6234] }
  , UnicodeDataRow { codepoint = 0xFA8D, canonicalCombiningClass = 0, canonicalDecomposition = [0x63C4] }
  , UnicodeDataRow { codepoint = 0xFA8E, canonicalCombiningClass = 0, canonicalDecomposition = [0x641C] }
  , UnicodeDataRow { codepoint = 0xFA8F, canonicalCombiningClass = 0, canonicalDecomposition = [0x6452] }
  , UnicodeDataRow { codepoint = 0xFA90, canonicalCombiningClass = 0, canonicalDecomposition = [0x6556] }
  , UnicodeDataRow { codepoint = 0xFA91, canonicalCombiningClass = 0, canonicalDecomposition = [0x6674] }
  , UnicodeDataRow { codepoint = 0xFA92, canonicalCombiningClass = 0, canonicalDecomposition = [0x6717] }
  , UnicodeDataRow { codepoint = 0xFA93, canonicalCombiningClass = 0, canonicalDecomposition = [0x671B] }
  , UnicodeDataRow { codepoint = 0xFA94, canonicalCombiningClass = 0, canonicalDecomposition = [0x6756] }
  , UnicodeDataRow { codepoint = 0xFA95, canonicalCombiningClass = 0, canonicalDecomposition = [0x6B79] }
  , UnicodeDataRow { codepoint = 0xFA96, canonicalCombiningClass = 0, canonicalDecomposition = [0x6BBA] }
  , UnicodeDataRow { codepoint = 0xFA97, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D41] }
  , UnicodeDataRow { codepoint = 0xFA98, canonicalCombiningClass = 0, canonicalDecomposition = [0x6EDB] }
  , UnicodeDataRow { codepoint = 0xFA99, canonicalCombiningClass = 0, canonicalDecomposition = [0x6ECB] }
  , UnicodeDataRow { codepoint = 0xFA9A, canonicalCombiningClass = 0, canonicalDecomposition = [0x6F22] }
  , UnicodeDataRow { codepoint = 0xFA9B, canonicalCombiningClass = 0, canonicalDecomposition = [0x701E] }
  , UnicodeDataRow { codepoint = 0xFA9C, canonicalCombiningClass = 0, canonicalDecomposition = [0x716E] }
  , UnicodeDataRow { codepoint = 0xFA9D, canonicalCombiningClass = 0, canonicalDecomposition = [0x77A7] }
  , UnicodeDataRow { codepoint = 0xFA9E, canonicalCombiningClass = 0, canonicalDecomposition = [0x7235] }
  , UnicodeDataRow { codepoint = 0xFA9F, canonicalCombiningClass = 0, canonicalDecomposition = [0x72AF] }
  , UnicodeDataRow { codepoint = 0xFAA0, canonicalCombiningClass = 0, canonicalDecomposition = [0x732A] }
  , UnicodeDataRow { codepoint = 0xFAA1, canonicalCombiningClass = 0, canonicalDecomposition = [0x7471] }
  , UnicodeDataRow { codepoint = 0xFAA2, canonicalCombiningClass = 0, canonicalDecomposition = [0x7506] }
  , UnicodeDataRow { codepoint = 0xFAA3, canonicalCombiningClass = 0, canonicalDecomposition = [0x753B] }
  , UnicodeDataRow { codepoint = 0xFAA4, canonicalCombiningClass = 0, canonicalDecomposition = [0x761D] }
  , UnicodeDataRow { codepoint = 0xFAA5, canonicalCombiningClass = 0, canonicalDecomposition = [0x761F] }
  , UnicodeDataRow { codepoint = 0xFAA6, canonicalCombiningClass = 0, canonicalDecomposition = [0x76CA] }
  , UnicodeDataRow { codepoint = 0xFAA7, canonicalCombiningClass = 0, canonicalDecomposition = [0x76DB] }
  , UnicodeDataRow { codepoint = 0xFAA8, canonicalCombiningClass = 0, canonicalDecomposition = [0x76F4] }
  , UnicodeDataRow { codepoint = 0xFAA9, canonicalCombiningClass = 0, canonicalDecomposition = [0x774A] }
  , UnicodeDataRow { codepoint = 0xFAAA, canonicalCombiningClass = 0, canonicalDecomposition = [0x7740] }
  , UnicodeDataRow { codepoint = 0xFAAB, canonicalCombiningClass = 0, canonicalDecomposition = [0x78CC] }
  , UnicodeDataRow { codepoint = 0xFAAC, canonicalCombiningClass = 0, canonicalDecomposition = [0x7AB1] }
  , UnicodeDataRow { codepoint = 0xFAAD, canonicalCombiningClass = 0, canonicalDecomposition = [0x7BC0] }
  , UnicodeDataRow { codepoint = 0xFAAE, canonicalCombiningClass = 0, canonicalDecomposition = [0x7C7B] }
  , UnicodeDataRow { codepoint = 0xFAAF, canonicalCombiningClass = 0, canonicalDecomposition = [0x7D5B] }
  , UnicodeDataRow { codepoint = 0xFAB0, canonicalCombiningClass = 0, canonicalDecomposition = [0x7DF4] }
  , UnicodeDataRow { codepoint = 0xFAB1, canonicalCombiningClass = 0, canonicalDecomposition = [0x7F3E] }
  , UnicodeDataRow { codepoint = 0xFAB2, canonicalCombiningClass = 0, canonicalDecomposition = [0x8005] }
  , UnicodeDataRow { codepoint = 0xFAB3, canonicalCombiningClass = 0, canonicalDecomposition = [0x8352] }
  , UnicodeDataRow { codepoint = 0xFAB4, canonicalCombiningClass = 0, canonicalDecomposition = [0x83EF] }
  , UnicodeDataRow { codepoint = 0xFAB5, canonicalCombiningClass = 0, canonicalDecomposition = [0x8779] }
  , UnicodeDataRow { codepoint = 0xFAB6, canonicalCombiningClass = 0, canonicalDecomposition = [0x8941] }
  , UnicodeDataRow { codepoint = 0xFAB7, canonicalCombiningClass = 0, canonicalDecomposition = [0x8986] }
  , UnicodeDataRow { codepoint = 0xFAB8, canonicalCombiningClass = 0, canonicalDecomposition = [0x8996] }
  , UnicodeDataRow { codepoint = 0xFAB9, canonicalCombiningClass = 0, canonicalDecomposition = [0x8ABF] }
  , UnicodeDataRow { codepoint = 0xFABA, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AF8] }
  , UnicodeDataRow { codepoint = 0xFABB, canonicalCombiningClass = 0, canonicalDecomposition = [0x8ACB] }
  , UnicodeDataRow { codepoint = 0xFABC, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B01] }
  , UnicodeDataRow { codepoint = 0xFABD, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AFE] }
  , UnicodeDataRow { codepoint = 0xFABE, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AED] }
  , UnicodeDataRow { codepoint = 0xFABF, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B39] }
  , UnicodeDataRow { codepoint = 0xFAC0, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B8A] }
  , UnicodeDataRow { codepoint = 0xFAC1, canonicalCombiningClass = 0, canonicalDecomposition = [0x8D08] }
  , UnicodeDataRow { codepoint = 0xFAC2, canonicalCombiningClass = 0, canonicalDecomposition = [0x8F38] }
  , UnicodeDataRow { codepoint = 0xFAC3, canonicalCombiningClass = 0, canonicalDecomposition = [0x9072] }
  , UnicodeDataRow { codepoint = 0xFAC4, canonicalCombiningClass = 0, canonicalDecomposition = [0x9199] }
  , UnicodeDataRow { codepoint = 0xFAC5, canonicalCombiningClass = 0, canonicalDecomposition = [0x9276] }
  , UnicodeDataRow { codepoint = 0xFAC6, canonicalCombiningClass = 0, canonicalDecomposition = [0x967C] }
  , UnicodeDataRow { codepoint = 0xFAC7, canonicalCombiningClass = 0, canonicalDecomposition = [0x96E3] }
  , UnicodeDataRow { codepoint = 0xFAC8, canonicalCombiningClass = 0, canonicalDecomposition = [0x9756] }
  , UnicodeDataRow { codepoint = 0xFAC9, canonicalCombiningClass = 0, canonicalDecomposition = [0x97DB] }
  , UnicodeDataRow { codepoint = 0xFACA, canonicalCombiningClass = 0, canonicalDecomposition = [0x97FF] }
  , UnicodeDataRow { codepoint = 0xFACB, canonicalCombiningClass = 0, canonicalDecomposition = [0x980B] }
  , UnicodeDataRow { codepoint = 0xFACC, canonicalCombiningClass = 0, canonicalDecomposition = [0x983B] }
  , UnicodeDataRow { codepoint = 0xFACD, canonicalCombiningClass = 0, canonicalDecomposition = [0x9B12] }
  , UnicodeDataRow { codepoint = 0xFACE, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F9C] }
  , UnicodeDataRow { codepoint = 0xFACF, canonicalCombiningClass = 0, canonicalDecomposition = [0x2284A] }
  , UnicodeDataRow { codepoint = 0xFAD0, canonicalCombiningClass = 0, canonicalDecomposition = [0x22844] }
  , UnicodeDataRow { codepoint = 0xFAD1, canonicalCombiningClass = 0, canonicalDecomposition = [0x233D5] }
  , UnicodeDataRow { codepoint = 0xFAD2, canonicalCombiningClass = 0, canonicalDecomposition = [0x3B9D] }
  , UnicodeDataRow { codepoint = 0xFAD3, canonicalCombiningClass = 0, canonicalDecomposition = [0x4018] }
  , UnicodeDataRow { codepoint = 0xFAD4, canonicalCombiningClass = 0, canonicalDecomposition = [0x4039] }
  , UnicodeDataRow { codepoint = 0xFAD5, canonicalCombiningClass = 0, canonicalDecomposition = [0x25249] }
  , UnicodeDataRow { codepoint = 0xFAD6, canonicalCombiningClass = 0, canonicalDecomposition = [0x25CD0] }
  , UnicodeDataRow { codepoint = 0xFAD7, canonicalCombiningClass = 0, canonicalDecomposition = [0x27ED3] }
  , UnicodeDataRow { codepoint = 0xFAD8, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F43] }
  , UnicodeDataRow { codepoint = 0xFAD9, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F8E] }
  , UnicodeDataRow { codepoint = 0xFB1D, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D9, 0x05B4] }
  , UnicodeDataRow { codepoint = 0xFB1E, canonicalCombiningClass = 26, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFB1F, canonicalCombiningClass = 0, canonicalDecomposition = [0x05F2, 0x05B7] }
  , UnicodeDataRow { codepoint = 0xFB2A, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E9, 0x05C1] }
  , UnicodeDataRow { codepoint = 0xFB2B, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E9, 0x05C2] }
  , UnicodeDataRow { codepoint = 0xFB2C, canonicalCombiningClass = 0, canonicalDecomposition = [0xFB49, 0x05C1] }
  , UnicodeDataRow { codepoint = 0xFB2D, canonicalCombiningClass = 0, canonicalDecomposition = [0xFB49, 0x05C2] }
  , UnicodeDataRow { codepoint = 0xFB2E, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D0, 0x05B7] }
  , UnicodeDataRow { codepoint = 0xFB2F, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D0, 0x05B8] }
  , UnicodeDataRow { codepoint = 0xFB30, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D0, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB31, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D1, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB32, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D2, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB33, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D3, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB34, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D4, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB35, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D5, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB36, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D6, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB38, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D8, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB39, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D9, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB3A, canonicalCombiningClass = 0, canonicalDecomposition = [0x05DA, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB3B, canonicalCombiningClass = 0, canonicalDecomposition = [0x05DB, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB3C, canonicalCombiningClass = 0, canonicalDecomposition = [0x05DC, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB3E, canonicalCombiningClass = 0, canonicalDecomposition = [0x05DE, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB40, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E0, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB41, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E1, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB43, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E3, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB44, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E4, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB46, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E6, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB47, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E7, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB48, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E8, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB49, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E9, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB4A, canonicalCombiningClass = 0, canonicalDecomposition = [0x05EA, 0x05BC] }
  , UnicodeDataRow { codepoint = 0xFB4B, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D5, 0x05B9] }
  , UnicodeDataRow { codepoint = 0xFB4C, canonicalCombiningClass = 0, canonicalDecomposition = [0x05D1, 0x05BF] }
  , UnicodeDataRow { codepoint = 0xFB4D, canonicalCombiningClass = 0, canonicalDecomposition = [0x05DB, 0x05BF] }
  , UnicodeDataRow { codepoint = 0xFB4E, canonicalCombiningClass = 0, canonicalDecomposition = [0x05E4, 0x05BF] }
  , UnicodeDataRow { codepoint = 0xFE20, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE21, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE22, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE23, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE24, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE25, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE26, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE27, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE28, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE29, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE2A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE2B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE2C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE2D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE2E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0xFE2F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x101FD, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x102E0, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10376, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10377, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10378, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10379, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1037A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x105C9, canonicalCombiningClass = 0, canonicalDecomposition = [0x105D2, 0x0307] }
  , UnicodeDataRow { codepoint = 0x105E4, canonicalCombiningClass = 0, canonicalDecomposition = [0x105DA, 0x0307] }
  , UnicodeDataRow { codepoint = 0x10A0D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10A0F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10A38, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10A39, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10A3A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10A3F, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10AE5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10AE6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D24, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D25, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D26, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D27, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D69, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D6A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D6B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D6C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10D6D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10EAB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10EAC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10EFA, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10EFB, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10EFD, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10EFE, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10EFF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F46, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F47, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F48, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F49, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F4A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F4B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F4C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F4D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F4E, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F4F, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F50, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F82, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F83, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F84, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x10F85, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11046, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11070, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1107F, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1109A, canonicalCombiningClass = 0, canonicalDecomposition = [0x11099, 0x110BA] }
  , UnicodeDataRow { codepoint = 0x1109C, canonicalCombiningClass = 0, canonicalDecomposition = [0x1109B, 0x110BA] }
  , UnicodeDataRow { codepoint = 0x110AB, canonicalCombiningClass = 0, canonicalDecomposition = [0x110A5, 0x110BA] }
  , UnicodeDataRow { codepoint = 0x110B9, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x110BA, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11100, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11101, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11102, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1112E, canonicalCombiningClass = 0, canonicalDecomposition = [0x11131, 0x11127] }
  , UnicodeDataRow { codepoint = 0x1112F, canonicalCombiningClass = 0, canonicalDecomposition = [0x11132, 0x11127] }
  , UnicodeDataRow { codepoint = 0x11133, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11134, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11173, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x111C0, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x111CA, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11235, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11236, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x112E9, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x112EA, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1133B, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1133C, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1134B, canonicalCombiningClass = 0, canonicalDecomposition = [0x11347, 0x1133E] }
  , UnicodeDataRow { codepoint = 0x1134C, canonicalCombiningClass = 0, canonicalDecomposition = [0x11347, 0x11357] }
  , UnicodeDataRow { codepoint = 0x1134D, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11366, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11367, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11368, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11369, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1136A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1136B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1136C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11370, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11371, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11372, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11373, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11374, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11383, canonicalCombiningClass = 0, canonicalDecomposition = [0x11382, 0x113C9] }
  , UnicodeDataRow { codepoint = 0x11385, canonicalCombiningClass = 0, canonicalDecomposition = [0x11384, 0x113BB] }
  , UnicodeDataRow { codepoint = 0x1138E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1138B, 0x113C2] }
  , UnicodeDataRow { codepoint = 0x11391, canonicalCombiningClass = 0, canonicalDecomposition = [0x11390, 0x113C9] }
  , UnicodeDataRow { codepoint = 0x113C5, canonicalCombiningClass = 0, canonicalDecomposition = [0x113C2, 0x113C2] }
  , UnicodeDataRow { codepoint = 0x113C7, canonicalCombiningClass = 0, canonicalDecomposition = [0x113C2, 0x113B8] }
  , UnicodeDataRow { codepoint = 0x113C8, canonicalCombiningClass = 0, canonicalDecomposition = [0x113C2, 0x113C9] }
  , UnicodeDataRow { codepoint = 0x113CE, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x113CF, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x113D0, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11442, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11446, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1145E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x114BB, canonicalCombiningClass = 0, canonicalDecomposition = [0x114B9, 0x114BA] }
  , UnicodeDataRow { codepoint = 0x114BC, canonicalCombiningClass = 0, canonicalDecomposition = [0x114B9, 0x114B0] }
  , UnicodeDataRow { codepoint = 0x114BE, canonicalCombiningClass = 0, canonicalDecomposition = [0x114B9, 0x114BD] }
  , UnicodeDataRow { codepoint = 0x114C2, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x114C3, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x115BA, canonicalCombiningClass = 0, canonicalDecomposition = [0x115B8, 0x115AF] }
  , UnicodeDataRow { codepoint = 0x115BB, canonicalCombiningClass = 0, canonicalDecomposition = [0x115B9, 0x115AF] }
  , UnicodeDataRow { codepoint = 0x115BF, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x115C0, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1163F, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x116B6, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x116B7, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1172B, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11839, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1183A, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11938, canonicalCombiningClass = 0, canonicalDecomposition = [0x11935, 0x11930] }
  , UnicodeDataRow { codepoint = 0x1193D, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1193E, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11943, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x119E0, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11A34, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11A47, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11A99, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11C3F, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11D42, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11D44, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11D45, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11D97, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11F41, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x11F42, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16121, canonicalCombiningClass = 0, canonicalDecomposition = [0x1611E, 0x1611E] }
  , UnicodeDataRow { codepoint = 0x16122, canonicalCombiningClass = 0, canonicalDecomposition = [0x1611E, 0x16129] }
  , UnicodeDataRow { codepoint = 0x16123, canonicalCombiningClass = 0, canonicalDecomposition = [0x1611E, 0x1611F] }
  , UnicodeDataRow { codepoint = 0x16124, canonicalCombiningClass = 0, canonicalDecomposition = [0x16129, 0x1611F] }
  , UnicodeDataRow { codepoint = 0x16125, canonicalCombiningClass = 0, canonicalDecomposition = [0x1611E, 0x16120] }
  , UnicodeDataRow { codepoint = 0x16126, canonicalCombiningClass = 0, canonicalDecomposition = [0x16121, 0x1611F] }
  , UnicodeDataRow { codepoint = 0x16127, canonicalCombiningClass = 0, canonicalDecomposition = [0x16122, 0x1611F] }
  , UnicodeDataRow { codepoint = 0x16128, canonicalCombiningClass = 0, canonicalDecomposition = [0x16121, 0x16120] }
  , UnicodeDataRow { codepoint = 0x1612F, canonicalCombiningClass = 9, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16AF0, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16AF1, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16AF2, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16AF3, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16AF4, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16B30, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16B31, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16B32, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16B33, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16B34, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16B35, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16B36, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16D68, canonicalCombiningClass = 0, canonicalDecomposition = [0x16D67, 0x16D67] }
  , UnicodeDataRow { codepoint = 0x16D69, canonicalCombiningClass = 0, canonicalDecomposition = [0x16D63, 0x16D67] }
  , UnicodeDataRow { codepoint = 0x16D6A, canonicalCombiningClass = 0, canonicalDecomposition = [0x16D69, 0x16D67] }
  , UnicodeDataRow { codepoint = 0x16FF0, canonicalCombiningClass = 6, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x16FF1, canonicalCombiningClass = 6, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1BC9E, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D15E, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D157, 0x1D165] }
  , UnicodeDataRow { codepoint = 0x1D15F, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D158, 0x1D165] }
  , UnicodeDataRow { codepoint = 0x1D160, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D15F, 0x1D16E] }
  , UnicodeDataRow { codepoint = 0x1D161, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D15F, 0x1D16F] }
  , UnicodeDataRow { codepoint = 0x1D162, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D15F, 0x1D170] }
  , UnicodeDataRow { codepoint = 0x1D163, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D15F, 0x1D171] }
  , UnicodeDataRow { codepoint = 0x1D164, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D15F, 0x1D172] }
  , UnicodeDataRow { codepoint = 0x1D165, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D166, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D167, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D168, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D169, canonicalCombiningClass = 1, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D16D, canonicalCombiningClass = 226, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D16E, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D16F, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D170, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D171, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D172, canonicalCombiningClass = 216, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D17B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D17C, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D17D, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D17E, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D17F, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D180, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D181, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D182, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D185, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D186, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D187, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D188, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D189, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D18A, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D18B, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D1AA, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D1AB, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D1AC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D1AD, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D1BB, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D1B9, 0x1D165] }
  , UnicodeDataRow { codepoint = 0x1D1BC, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D1BA, 0x1D165] }
  , UnicodeDataRow { codepoint = 0x1D1BD, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D1BB, 0x1D16E] }
  , UnicodeDataRow { codepoint = 0x1D1BE, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D1BC, 0x1D16E] }
  , UnicodeDataRow { codepoint = 0x1D1BF, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D1BB, 0x1D16F] }
  , UnicodeDataRow { codepoint = 0x1D1C0, canonicalCombiningClass = 0, canonicalDecomposition = [0x1D1BC, 0x1D16F] }
  , UnicodeDataRow { codepoint = 0x1D242, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D243, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1D244, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E000, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E001, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E002, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E003, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E004, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E005, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E006, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E008, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E009, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E00A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E00B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E00C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E00D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E00E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E00F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E010, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E011, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E012, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E013, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E014, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E015, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E016, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E017, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E018, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E01B, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E01C, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E01D, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E01E, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E01F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E020, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E021, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E023, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E024, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E026, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E027, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E028, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E029, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E02A, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E08F, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E130, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E131, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E132, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E133, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E134, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E135, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E136, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E2AE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E2EC, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E2ED, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E2EE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E2EF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E4EC, canonicalCombiningClass = 232, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E4ED, canonicalCombiningClass = 232, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E4EE, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E4EF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E5EE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E5EF, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E6E3, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E6E6, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E6EE, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E6EF, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E6F5, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E8D0, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E8D1, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E8D2, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E8D3, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E8D4, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E8D5, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E8D6, canonicalCombiningClass = 220, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E944, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E945, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E946, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E947, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E948, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E949, canonicalCombiningClass = 230, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x1E94A, canonicalCombiningClass = 7, canonicalDecomposition = [] }
  , UnicodeDataRow { codepoint = 0x2F800, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E3D] }
  , UnicodeDataRow { codepoint = 0x2F801, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E38] }
  , UnicodeDataRow { codepoint = 0x2F802, canonicalCombiningClass = 0, canonicalDecomposition = [0x4E41] }
  , UnicodeDataRow { codepoint = 0x2F803, canonicalCombiningClass = 0, canonicalDecomposition = [0x20122] }
  , UnicodeDataRow { codepoint = 0x2F804, canonicalCombiningClass = 0, canonicalDecomposition = [0x4F60] }
  , UnicodeDataRow { codepoint = 0x2F805, canonicalCombiningClass = 0, canonicalDecomposition = [0x4FAE] }
  , UnicodeDataRow { codepoint = 0x2F806, canonicalCombiningClass = 0, canonicalDecomposition = [0x4FBB] }
  , UnicodeDataRow { codepoint = 0x2F807, canonicalCombiningClass = 0, canonicalDecomposition = [0x5002] }
  , UnicodeDataRow { codepoint = 0x2F808, canonicalCombiningClass = 0, canonicalDecomposition = [0x507A] }
  , UnicodeDataRow { codepoint = 0x2F809, canonicalCombiningClass = 0, canonicalDecomposition = [0x5099] }
  , UnicodeDataRow { codepoint = 0x2F80A, canonicalCombiningClass = 0, canonicalDecomposition = [0x50E7] }
  , UnicodeDataRow { codepoint = 0x2F80B, canonicalCombiningClass = 0, canonicalDecomposition = [0x50CF] }
  , UnicodeDataRow { codepoint = 0x2F80C, canonicalCombiningClass = 0, canonicalDecomposition = [0x349E] }
  , UnicodeDataRow { codepoint = 0x2F80D, canonicalCombiningClass = 0, canonicalDecomposition = [0x2063A] }
  , UnicodeDataRow { codepoint = 0x2F80E, canonicalCombiningClass = 0, canonicalDecomposition = [0x514D] }
  , UnicodeDataRow { codepoint = 0x2F80F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5154] }
  , UnicodeDataRow { codepoint = 0x2F810, canonicalCombiningClass = 0, canonicalDecomposition = [0x5164] }
  , UnicodeDataRow { codepoint = 0x2F811, canonicalCombiningClass = 0, canonicalDecomposition = [0x5177] }
  , UnicodeDataRow { codepoint = 0x2F812, canonicalCombiningClass = 0, canonicalDecomposition = [0x2051C] }
  , UnicodeDataRow { codepoint = 0x2F813, canonicalCombiningClass = 0, canonicalDecomposition = [0x34B9] }
  , UnicodeDataRow { codepoint = 0x2F814, canonicalCombiningClass = 0, canonicalDecomposition = [0x5167] }
  , UnicodeDataRow { codepoint = 0x2F815, canonicalCombiningClass = 0, canonicalDecomposition = [0x518D] }
  , UnicodeDataRow { codepoint = 0x2F816, canonicalCombiningClass = 0, canonicalDecomposition = [0x2054B] }
  , UnicodeDataRow { codepoint = 0x2F817, canonicalCombiningClass = 0, canonicalDecomposition = [0x5197] }
  , UnicodeDataRow { codepoint = 0x2F818, canonicalCombiningClass = 0, canonicalDecomposition = [0x51A4] }
  , UnicodeDataRow { codepoint = 0x2F819, canonicalCombiningClass = 0, canonicalDecomposition = [0x4ECC] }
  , UnicodeDataRow { codepoint = 0x2F81A, canonicalCombiningClass = 0, canonicalDecomposition = [0x51AC] }
  , UnicodeDataRow { codepoint = 0x2F81B, canonicalCombiningClass = 0, canonicalDecomposition = [0x51B5] }
  , UnicodeDataRow { codepoint = 0x2F81C, canonicalCombiningClass = 0, canonicalDecomposition = [0x291DF] }
  , UnicodeDataRow { codepoint = 0x2F81D, canonicalCombiningClass = 0, canonicalDecomposition = [0x51F5] }
  , UnicodeDataRow { codepoint = 0x2F81E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5203] }
  , UnicodeDataRow { codepoint = 0x2F81F, canonicalCombiningClass = 0, canonicalDecomposition = [0x34DF] }
  , UnicodeDataRow { codepoint = 0x2F820, canonicalCombiningClass = 0, canonicalDecomposition = [0x523B] }
  , UnicodeDataRow { codepoint = 0x2F821, canonicalCombiningClass = 0, canonicalDecomposition = [0x5246] }
  , UnicodeDataRow { codepoint = 0x2F822, canonicalCombiningClass = 0, canonicalDecomposition = [0x5272] }
  , UnicodeDataRow { codepoint = 0x2F823, canonicalCombiningClass = 0, canonicalDecomposition = [0x5277] }
  , UnicodeDataRow { codepoint = 0x2F824, canonicalCombiningClass = 0, canonicalDecomposition = [0x3515] }
  , UnicodeDataRow { codepoint = 0x2F825, canonicalCombiningClass = 0, canonicalDecomposition = [0x52C7] }
  , UnicodeDataRow { codepoint = 0x2F826, canonicalCombiningClass = 0, canonicalDecomposition = [0x52C9] }
  , UnicodeDataRow { codepoint = 0x2F827, canonicalCombiningClass = 0, canonicalDecomposition = [0x52E4] }
  , UnicodeDataRow { codepoint = 0x2F828, canonicalCombiningClass = 0, canonicalDecomposition = [0x52FA] }
  , UnicodeDataRow { codepoint = 0x2F829, canonicalCombiningClass = 0, canonicalDecomposition = [0x5305] }
  , UnicodeDataRow { codepoint = 0x2F82A, canonicalCombiningClass = 0, canonicalDecomposition = [0x5306] }
  , UnicodeDataRow { codepoint = 0x2F82B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5317] }
  , UnicodeDataRow { codepoint = 0x2F82C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5349] }
  , UnicodeDataRow { codepoint = 0x2F82D, canonicalCombiningClass = 0, canonicalDecomposition = [0x5351] }
  , UnicodeDataRow { codepoint = 0x2F82E, canonicalCombiningClass = 0, canonicalDecomposition = [0x535A] }
  , UnicodeDataRow { codepoint = 0x2F82F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5373] }
  , UnicodeDataRow { codepoint = 0x2F830, canonicalCombiningClass = 0, canonicalDecomposition = [0x537D] }
  , UnicodeDataRow { codepoint = 0x2F831, canonicalCombiningClass = 0, canonicalDecomposition = [0x537F] }
  , UnicodeDataRow { codepoint = 0x2F832, canonicalCombiningClass = 0, canonicalDecomposition = [0x537F] }
  , UnicodeDataRow { codepoint = 0x2F833, canonicalCombiningClass = 0, canonicalDecomposition = [0x537F] }
  , UnicodeDataRow { codepoint = 0x2F834, canonicalCombiningClass = 0, canonicalDecomposition = [0x20A2C] }
  , UnicodeDataRow { codepoint = 0x2F835, canonicalCombiningClass = 0, canonicalDecomposition = [0x7070] }
  , UnicodeDataRow { codepoint = 0x2F836, canonicalCombiningClass = 0, canonicalDecomposition = [0x53CA] }
  , UnicodeDataRow { codepoint = 0x2F837, canonicalCombiningClass = 0, canonicalDecomposition = [0x53DF] }
  , UnicodeDataRow { codepoint = 0x2F838, canonicalCombiningClass = 0, canonicalDecomposition = [0x20B63] }
  , UnicodeDataRow { codepoint = 0x2F839, canonicalCombiningClass = 0, canonicalDecomposition = [0x53EB] }
  , UnicodeDataRow { codepoint = 0x2F83A, canonicalCombiningClass = 0, canonicalDecomposition = [0x53F1] }
  , UnicodeDataRow { codepoint = 0x2F83B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5406] }
  , UnicodeDataRow { codepoint = 0x2F83C, canonicalCombiningClass = 0, canonicalDecomposition = [0x549E] }
  , UnicodeDataRow { codepoint = 0x2F83D, canonicalCombiningClass = 0, canonicalDecomposition = [0x5438] }
  , UnicodeDataRow { codepoint = 0x2F83E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5448] }
  , UnicodeDataRow { codepoint = 0x2F83F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5468] }
  , UnicodeDataRow { codepoint = 0x2F840, canonicalCombiningClass = 0, canonicalDecomposition = [0x54A2] }
  , UnicodeDataRow { codepoint = 0x2F841, canonicalCombiningClass = 0, canonicalDecomposition = [0x54F6] }
  , UnicodeDataRow { codepoint = 0x2F842, canonicalCombiningClass = 0, canonicalDecomposition = [0x5510] }
  , UnicodeDataRow { codepoint = 0x2F843, canonicalCombiningClass = 0, canonicalDecomposition = [0x5553] }
  , UnicodeDataRow { codepoint = 0x2F844, canonicalCombiningClass = 0, canonicalDecomposition = [0x5563] }
  , UnicodeDataRow { codepoint = 0x2F845, canonicalCombiningClass = 0, canonicalDecomposition = [0x5584] }
  , UnicodeDataRow { codepoint = 0x2F846, canonicalCombiningClass = 0, canonicalDecomposition = [0x5584] }
  , UnicodeDataRow { codepoint = 0x2F847, canonicalCombiningClass = 0, canonicalDecomposition = [0x5599] }
  , UnicodeDataRow { codepoint = 0x2F848, canonicalCombiningClass = 0, canonicalDecomposition = [0x55AB] }
  , UnicodeDataRow { codepoint = 0x2F849, canonicalCombiningClass = 0, canonicalDecomposition = [0x55B3] }
  , UnicodeDataRow { codepoint = 0x2F84A, canonicalCombiningClass = 0, canonicalDecomposition = [0x55C2] }
  , UnicodeDataRow { codepoint = 0x2F84B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5716] }
  , UnicodeDataRow { codepoint = 0x2F84C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5606] }
  , UnicodeDataRow { codepoint = 0x2F84D, canonicalCombiningClass = 0, canonicalDecomposition = [0x5717] }
  , UnicodeDataRow { codepoint = 0x2F84E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5651] }
  , UnicodeDataRow { codepoint = 0x2F84F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5674] }
  , UnicodeDataRow { codepoint = 0x2F850, canonicalCombiningClass = 0, canonicalDecomposition = [0x5207] }
  , UnicodeDataRow { codepoint = 0x2F851, canonicalCombiningClass = 0, canonicalDecomposition = [0x58EE] }
  , UnicodeDataRow { codepoint = 0x2F852, canonicalCombiningClass = 0, canonicalDecomposition = [0x57CE] }
  , UnicodeDataRow { codepoint = 0x2F853, canonicalCombiningClass = 0, canonicalDecomposition = [0x57F4] }
  , UnicodeDataRow { codepoint = 0x2F854, canonicalCombiningClass = 0, canonicalDecomposition = [0x580D] }
  , UnicodeDataRow { codepoint = 0x2F855, canonicalCombiningClass = 0, canonicalDecomposition = [0x578B] }
  , UnicodeDataRow { codepoint = 0x2F856, canonicalCombiningClass = 0, canonicalDecomposition = [0x5832] }
  , UnicodeDataRow { codepoint = 0x2F857, canonicalCombiningClass = 0, canonicalDecomposition = [0x5831] }
  , UnicodeDataRow { codepoint = 0x2F858, canonicalCombiningClass = 0, canonicalDecomposition = [0x58AC] }
  , UnicodeDataRow { codepoint = 0x2F859, canonicalCombiningClass = 0, canonicalDecomposition = [0x214E4] }
  , UnicodeDataRow { codepoint = 0x2F85A, canonicalCombiningClass = 0, canonicalDecomposition = [0x58F2] }
  , UnicodeDataRow { codepoint = 0x2F85B, canonicalCombiningClass = 0, canonicalDecomposition = [0x58F7] }
  , UnicodeDataRow { codepoint = 0x2F85C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5906] }
  , UnicodeDataRow { codepoint = 0x2F85D, canonicalCombiningClass = 0, canonicalDecomposition = [0x591A] }
  , UnicodeDataRow { codepoint = 0x2F85E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5922] }
  , UnicodeDataRow { codepoint = 0x2F85F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5962] }
  , UnicodeDataRow { codepoint = 0x2F860, canonicalCombiningClass = 0, canonicalDecomposition = [0x216A8] }
  , UnicodeDataRow { codepoint = 0x2F861, canonicalCombiningClass = 0, canonicalDecomposition = [0x216EA] }
  , UnicodeDataRow { codepoint = 0x2F862, canonicalCombiningClass = 0, canonicalDecomposition = [0x59EC] }
  , UnicodeDataRow { codepoint = 0x2F863, canonicalCombiningClass = 0, canonicalDecomposition = [0x5A1B] }
  , UnicodeDataRow { codepoint = 0x2F864, canonicalCombiningClass = 0, canonicalDecomposition = [0x5A27] }
  , UnicodeDataRow { codepoint = 0x2F865, canonicalCombiningClass = 0, canonicalDecomposition = [0x59D8] }
  , UnicodeDataRow { codepoint = 0x2F866, canonicalCombiningClass = 0, canonicalDecomposition = [0x5A66] }
  , UnicodeDataRow { codepoint = 0x2F867, canonicalCombiningClass = 0, canonicalDecomposition = [0x36EE] }
  , UnicodeDataRow { codepoint = 0x2F868, canonicalCombiningClass = 0, canonicalDecomposition = [0x36FC] }
  , UnicodeDataRow { codepoint = 0x2F869, canonicalCombiningClass = 0, canonicalDecomposition = [0x5B08] }
  , UnicodeDataRow { codepoint = 0x2F86A, canonicalCombiningClass = 0, canonicalDecomposition = [0x5B3E] }
  , UnicodeDataRow { codepoint = 0x2F86B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5B3E] }
  , UnicodeDataRow { codepoint = 0x2F86C, canonicalCombiningClass = 0, canonicalDecomposition = [0x219C8] }
  , UnicodeDataRow { codepoint = 0x2F86D, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BC3] }
  , UnicodeDataRow { codepoint = 0x2F86E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BD8] }
  , UnicodeDataRow { codepoint = 0x2F86F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BE7] }
  , UnicodeDataRow { codepoint = 0x2F870, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BF3] }
  , UnicodeDataRow { codepoint = 0x2F871, canonicalCombiningClass = 0, canonicalDecomposition = [0x21B18] }
  , UnicodeDataRow { codepoint = 0x2F872, canonicalCombiningClass = 0, canonicalDecomposition = [0x5BFF] }
  , UnicodeDataRow { codepoint = 0x2F873, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C06] }
  , UnicodeDataRow { codepoint = 0x2F874, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F53] }
  , UnicodeDataRow { codepoint = 0x2F875, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C22] }
  , UnicodeDataRow { codepoint = 0x2F876, canonicalCombiningClass = 0, canonicalDecomposition = [0x3781] }
  , UnicodeDataRow { codepoint = 0x2F877, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C60] }
  , UnicodeDataRow { codepoint = 0x2F878, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C6E] }
  , UnicodeDataRow { codepoint = 0x2F879, canonicalCombiningClass = 0, canonicalDecomposition = [0x5CC0] }
  , UnicodeDataRow { codepoint = 0x2F87A, canonicalCombiningClass = 0, canonicalDecomposition = [0x5C8D] }
  , UnicodeDataRow { codepoint = 0x2F87B, canonicalCombiningClass = 0, canonicalDecomposition = [0x21DE4] }
  , UnicodeDataRow { codepoint = 0x2F87C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5D43] }
  , UnicodeDataRow { codepoint = 0x2F87D, canonicalCombiningClass = 0, canonicalDecomposition = [0x21DE6] }
  , UnicodeDataRow { codepoint = 0x2F87E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5D6E] }
  , UnicodeDataRow { codepoint = 0x2F87F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5D6B] }
  , UnicodeDataRow { codepoint = 0x2F880, canonicalCombiningClass = 0, canonicalDecomposition = [0x5D7C] }
  , UnicodeDataRow { codepoint = 0x2F881, canonicalCombiningClass = 0, canonicalDecomposition = [0x5DE1] }
  , UnicodeDataRow { codepoint = 0x2F882, canonicalCombiningClass = 0, canonicalDecomposition = [0x5DE2] }
  , UnicodeDataRow { codepoint = 0x2F883, canonicalCombiningClass = 0, canonicalDecomposition = [0x382F] }
  , UnicodeDataRow { codepoint = 0x2F884, canonicalCombiningClass = 0, canonicalDecomposition = [0x5DFD] }
  , UnicodeDataRow { codepoint = 0x2F885, canonicalCombiningClass = 0, canonicalDecomposition = [0x5E28] }
  , UnicodeDataRow { codepoint = 0x2F886, canonicalCombiningClass = 0, canonicalDecomposition = [0x5E3D] }
  , UnicodeDataRow { codepoint = 0x2F887, canonicalCombiningClass = 0, canonicalDecomposition = [0x5E69] }
  , UnicodeDataRow { codepoint = 0x2F888, canonicalCombiningClass = 0, canonicalDecomposition = [0x3862] }
  , UnicodeDataRow { codepoint = 0x2F889, canonicalCombiningClass = 0, canonicalDecomposition = [0x22183] }
  , UnicodeDataRow { codepoint = 0x2F88A, canonicalCombiningClass = 0, canonicalDecomposition = [0x387C] }
  , UnicodeDataRow { codepoint = 0x2F88B, canonicalCombiningClass = 0, canonicalDecomposition = [0x5EB0] }
  , UnicodeDataRow { codepoint = 0x2F88C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5EB3] }
  , UnicodeDataRow { codepoint = 0x2F88D, canonicalCombiningClass = 0, canonicalDecomposition = [0x5EB6] }
  , UnicodeDataRow { codepoint = 0x2F88E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5ECA] }
  , UnicodeDataRow { codepoint = 0x2F88F, canonicalCombiningClass = 0, canonicalDecomposition = [0x2A392] }
  , UnicodeDataRow { codepoint = 0x2F890, canonicalCombiningClass = 0, canonicalDecomposition = [0x5EFE] }
  , UnicodeDataRow { codepoint = 0x2F891, canonicalCombiningClass = 0, canonicalDecomposition = [0x22331] }
  , UnicodeDataRow { codepoint = 0x2F892, canonicalCombiningClass = 0, canonicalDecomposition = [0x22331] }
  , UnicodeDataRow { codepoint = 0x2F893, canonicalCombiningClass = 0, canonicalDecomposition = [0x8201] }
  , UnicodeDataRow { codepoint = 0x2F894, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F22] }
  , UnicodeDataRow { codepoint = 0x2F895, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F22] }
  , UnicodeDataRow { codepoint = 0x2F896, canonicalCombiningClass = 0, canonicalDecomposition = [0x38C7] }
  , UnicodeDataRow { codepoint = 0x2F897, canonicalCombiningClass = 0, canonicalDecomposition = [0x232B8] }
  , UnicodeDataRow { codepoint = 0x2F898, canonicalCombiningClass = 0, canonicalDecomposition = [0x261DA] }
  , UnicodeDataRow { codepoint = 0x2F899, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F62] }
  , UnicodeDataRow { codepoint = 0x2F89A, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F6B] }
  , UnicodeDataRow { codepoint = 0x2F89B, canonicalCombiningClass = 0, canonicalDecomposition = [0x38E3] }
  , UnicodeDataRow { codepoint = 0x2F89C, canonicalCombiningClass = 0, canonicalDecomposition = [0x5F9A] }
  , UnicodeDataRow { codepoint = 0x2F89D, canonicalCombiningClass = 0, canonicalDecomposition = [0x5FCD] }
  , UnicodeDataRow { codepoint = 0x2F89E, canonicalCombiningClass = 0, canonicalDecomposition = [0x5FD7] }
  , UnicodeDataRow { codepoint = 0x2F89F, canonicalCombiningClass = 0, canonicalDecomposition = [0x5FF9] }
  , UnicodeDataRow { codepoint = 0x2F8A0, canonicalCombiningClass = 0, canonicalDecomposition = [0x6081] }
  , UnicodeDataRow { codepoint = 0x2F8A1, canonicalCombiningClass = 0, canonicalDecomposition = [0x393A] }
  , UnicodeDataRow { codepoint = 0x2F8A2, canonicalCombiningClass = 0, canonicalDecomposition = [0x391C] }
  , UnicodeDataRow { codepoint = 0x2F8A3, canonicalCombiningClass = 0, canonicalDecomposition = [0x6094] }
  , UnicodeDataRow { codepoint = 0x2F8A4, canonicalCombiningClass = 0, canonicalDecomposition = [0x226D4] }
  , UnicodeDataRow { codepoint = 0x2F8A5, canonicalCombiningClass = 0, canonicalDecomposition = [0x60C7] }
  , UnicodeDataRow { codepoint = 0x2F8A6, canonicalCombiningClass = 0, canonicalDecomposition = [0x6148] }
  , UnicodeDataRow { codepoint = 0x2F8A7, canonicalCombiningClass = 0, canonicalDecomposition = [0x614C] }
  , UnicodeDataRow { codepoint = 0x2F8A8, canonicalCombiningClass = 0, canonicalDecomposition = [0x614E] }
  , UnicodeDataRow { codepoint = 0x2F8A9, canonicalCombiningClass = 0, canonicalDecomposition = [0x614C] }
  , UnicodeDataRow { codepoint = 0x2F8AA, canonicalCombiningClass = 0, canonicalDecomposition = [0x617A] }
  , UnicodeDataRow { codepoint = 0x2F8AB, canonicalCombiningClass = 0, canonicalDecomposition = [0x618E] }
  , UnicodeDataRow { codepoint = 0x2F8AC, canonicalCombiningClass = 0, canonicalDecomposition = [0x61B2] }
  , UnicodeDataRow { codepoint = 0x2F8AD, canonicalCombiningClass = 0, canonicalDecomposition = [0x61A4] }
  , UnicodeDataRow { codepoint = 0x2F8AE, canonicalCombiningClass = 0, canonicalDecomposition = [0x61AF] }
  , UnicodeDataRow { codepoint = 0x2F8AF, canonicalCombiningClass = 0, canonicalDecomposition = [0x61DE] }
  , UnicodeDataRow { codepoint = 0x2F8B0, canonicalCombiningClass = 0, canonicalDecomposition = [0x61F2] }
  , UnicodeDataRow { codepoint = 0x2F8B1, canonicalCombiningClass = 0, canonicalDecomposition = [0x61F6] }
  , UnicodeDataRow { codepoint = 0x2F8B2, canonicalCombiningClass = 0, canonicalDecomposition = [0x6210] }
  , UnicodeDataRow { codepoint = 0x2F8B3, canonicalCombiningClass = 0, canonicalDecomposition = [0x621B] }
  , UnicodeDataRow { codepoint = 0x2F8B4, canonicalCombiningClass = 0, canonicalDecomposition = [0x625D] }
  , UnicodeDataRow { codepoint = 0x2F8B5, canonicalCombiningClass = 0, canonicalDecomposition = [0x62B1] }
  , UnicodeDataRow { codepoint = 0x2F8B6, canonicalCombiningClass = 0, canonicalDecomposition = [0x62D4] }
  , UnicodeDataRow { codepoint = 0x2F8B7, canonicalCombiningClass = 0, canonicalDecomposition = [0x6350] }
  , UnicodeDataRow { codepoint = 0x2F8B8, canonicalCombiningClass = 0, canonicalDecomposition = [0x22B0C] }
  , UnicodeDataRow { codepoint = 0x2F8B9, canonicalCombiningClass = 0, canonicalDecomposition = [0x633D] }
  , UnicodeDataRow { codepoint = 0x2F8BA, canonicalCombiningClass = 0, canonicalDecomposition = [0x62FC] }
  , UnicodeDataRow { codepoint = 0x2F8BB, canonicalCombiningClass = 0, canonicalDecomposition = [0x6368] }
  , UnicodeDataRow { codepoint = 0x2F8BC, canonicalCombiningClass = 0, canonicalDecomposition = [0x6383] }
  , UnicodeDataRow { codepoint = 0x2F8BD, canonicalCombiningClass = 0, canonicalDecomposition = [0x63E4] }
  , UnicodeDataRow { codepoint = 0x2F8BE, canonicalCombiningClass = 0, canonicalDecomposition = [0x22BF1] }
  , UnicodeDataRow { codepoint = 0x2F8BF, canonicalCombiningClass = 0, canonicalDecomposition = [0x6422] }
  , UnicodeDataRow { codepoint = 0x2F8C0, canonicalCombiningClass = 0, canonicalDecomposition = [0x63C5] }
  , UnicodeDataRow { codepoint = 0x2F8C1, canonicalCombiningClass = 0, canonicalDecomposition = [0x63A9] }
  , UnicodeDataRow { codepoint = 0x2F8C2, canonicalCombiningClass = 0, canonicalDecomposition = [0x3A2E] }
  , UnicodeDataRow { codepoint = 0x2F8C3, canonicalCombiningClass = 0, canonicalDecomposition = [0x6469] }
  , UnicodeDataRow { codepoint = 0x2F8C4, canonicalCombiningClass = 0, canonicalDecomposition = [0x647E] }
  , UnicodeDataRow { codepoint = 0x2F8C5, canonicalCombiningClass = 0, canonicalDecomposition = [0x649D] }
  , UnicodeDataRow { codepoint = 0x2F8C6, canonicalCombiningClass = 0, canonicalDecomposition = [0x6477] }
  , UnicodeDataRow { codepoint = 0x2F8C7, canonicalCombiningClass = 0, canonicalDecomposition = [0x3A6C] }
  , UnicodeDataRow { codepoint = 0x2F8C8, canonicalCombiningClass = 0, canonicalDecomposition = [0x654F] }
  , UnicodeDataRow { codepoint = 0x2F8C9, canonicalCombiningClass = 0, canonicalDecomposition = [0x656C] }
  , UnicodeDataRow { codepoint = 0x2F8CA, canonicalCombiningClass = 0, canonicalDecomposition = [0x2300A] }
  , UnicodeDataRow { codepoint = 0x2F8CB, canonicalCombiningClass = 0, canonicalDecomposition = [0x65E3] }
  , UnicodeDataRow { codepoint = 0x2F8CC, canonicalCombiningClass = 0, canonicalDecomposition = [0x66F8] }
  , UnicodeDataRow { codepoint = 0x2F8CD, canonicalCombiningClass = 0, canonicalDecomposition = [0x6649] }
  , UnicodeDataRow { codepoint = 0x2F8CE, canonicalCombiningClass = 0, canonicalDecomposition = [0x3B19] }
  , UnicodeDataRow { codepoint = 0x2F8CF, canonicalCombiningClass = 0, canonicalDecomposition = [0x6691] }
  , UnicodeDataRow { codepoint = 0x2F8D0, canonicalCombiningClass = 0, canonicalDecomposition = [0x3B08] }
  , UnicodeDataRow { codepoint = 0x2F8D1, canonicalCombiningClass = 0, canonicalDecomposition = [0x3AE4] }
  , UnicodeDataRow { codepoint = 0x2F8D2, canonicalCombiningClass = 0, canonicalDecomposition = [0x5192] }
  , UnicodeDataRow { codepoint = 0x2F8D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x5195] }
  , UnicodeDataRow { codepoint = 0x2F8D4, canonicalCombiningClass = 0, canonicalDecomposition = [0x6700] }
  , UnicodeDataRow { codepoint = 0x2F8D5, canonicalCombiningClass = 0, canonicalDecomposition = [0x669C] }
  , UnicodeDataRow { codepoint = 0x2F8D6, canonicalCombiningClass = 0, canonicalDecomposition = [0x80AD] }
  , UnicodeDataRow { codepoint = 0x2F8D7, canonicalCombiningClass = 0, canonicalDecomposition = [0x43D9] }
  , UnicodeDataRow { codepoint = 0x2F8D8, canonicalCombiningClass = 0, canonicalDecomposition = [0x6717] }
  , UnicodeDataRow { codepoint = 0x2F8D9, canonicalCombiningClass = 0, canonicalDecomposition = [0x671B] }
  , UnicodeDataRow { codepoint = 0x2F8DA, canonicalCombiningClass = 0, canonicalDecomposition = [0x6721] }
  , UnicodeDataRow { codepoint = 0x2F8DB, canonicalCombiningClass = 0, canonicalDecomposition = [0x675E] }
  , UnicodeDataRow { codepoint = 0x2F8DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x6753] }
  , UnicodeDataRow { codepoint = 0x2F8DD, canonicalCombiningClass = 0, canonicalDecomposition = [0x233C3] }
  , UnicodeDataRow { codepoint = 0x2F8DE, canonicalCombiningClass = 0, canonicalDecomposition = [0x3B49] }
  , UnicodeDataRow { codepoint = 0x2F8DF, canonicalCombiningClass = 0, canonicalDecomposition = [0x67FA] }
  , UnicodeDataRow { codepoint = 0x2F8E0, canonicalCombiningClass = 0, canonicalDecomposition = [0x6785] }
  , UnicodeDataRow { codepoint = 0x2F8E1, canonicalCombiningClass = 0, canonicalDecomposition = [0x6852] }
  , UnicodeDataRow { codepoint = 0x2F8E2, canonicalCombiningClass = 0, canonicalDecomposition = [0x6885] }
  , UnicodeDataRow { codepoint = 0x2F8E3, canonicalCombiningClass = 0, canonicalDecomposition = [0x2346D] }
  , UnicodeDataRow { codepoint = 0x2F8E4, canonicalCombiningClass = 0, canonicalDecomposition = [0x688E] }
  , UnicodeDataRow { codepoint = 0x2F8E5, canonicalCombiningClass = 0, canonicalDecomposition = [0x681F] }
  , UnicodeDataRow { codepoint = 0x2F8E6, canonicalCombiningClass = 0, canonicalDecomposition = [0x6914] }
  , UnicodeDataRow { codepoint = 0x2F8E7, canonicalCombiningClass = 0, canonicalDecomposition = [0x3B9D] }
  , UnicodeDataRow { codepoint = 0x2F8E8, canonicalCombiningClass = 0, canonicalDecomposition = [0x6942] }
  , UnicodeDataRow { codepoint = 0x2F8E9, canonicalCombiningClass = 0, canonicalDecomposition = [0x69A3] }
  , UnicodeDataRow { codepoint = 0x2F8EA, canonicalCombiningClass = 0, canonicalDecomposition = [0x69EA] }
  , UnicodeDataRow { codepoint = 0x2F8EB, canonicalCombiningClass = 0, canonicalDecomposition = [0x6AA8] }
  , UnicodeDataRow { codepoint = 0x2F8EC, canonicalCombiningClass = 0, canonicalDecomposition = [0x236A3] }
  , UnicodeDataRow { codepoint = 0x2F8ED, canonicalCombiningClass = 0, canonicalDecomposition = [0x6ADB] }
  , UnicodeDataRow { codepoint = 0x2F8EE, canonicalCombiningClass = 0, canonicalDecomposition = [0x3C18] }
  , UnicodeDataRow { codepoint = 0x2F8EF, canonicalCombiningClass = 0, canonicalDecomposition = [0x6B21] }
  , UnicodeDataRow { codepoint = 0x2F8F0, canonicalCombiningClass = 0, canonicalDecomposition = [0x238A7] }
  , UnicodeDataRow { codepoint = 0x2F8F1, canonicalCombiningClass = 0, canonicalDecomposition = [0x6B54] }
  , UnicodeDataRow { codepoint = 0x2F8F2, canonicalCombiningClass = 0, canonicalDecomposition = [0x3C4E] }
  , UnicodeDataRow { codepoint = 0x2F8F3, canonicalCombiningClass = 0, canonicalDecomposition = [0x6B72] }
  , UnicodeDataRow { codepoint = 0x2F8F4, canonicalCombiningClass = 0, canonicalDecomposition = [0x6B9F] }
  , UnicodeDataRow { codepoint = 0x2F8F5, canonicalCombiningClass = 0, canonicalDecomposition = [0x6BBA] }
  , UnicodeDataRow { codepoint = 0x2F8F6, canonicalCombiningClass = 0, canonicalDecomposition = [0x6BBB] }
  , UnicodeDataRow { codepoint = 0x2F8F7, canonicalCombiningClass = 0, canonicalDecomposition = [0x23A8D] }
  , UnicodeDataRow { codepoint = 0x2F8F8, canonicalCombiningClass = 0, canonicalDecomposition = [0x21D0B] }
  , UnicodeDataRow { codepoint = 0x2F8F9, canonicalCombiningClass = 0, canonicalDecomposition = [0x23AFA] }
  , UnicodeDataRow { codepoint = 0x2F8FA, canonicalCombiningClass = 0, canonicalDecomposition = [0x6C4E] }
  , UnicodeDataRow { codepoint = 0x2F8FB, canonicalCombiningClass = 0, canonicalDecomposition = [0x23CBC] }
  , UnicodeDataRow { codepoint = 0x2F8FC, canonicalCombiningClass = 0, canonicalDecomposition = [0x6CBF] }
  , UnicodeDataRow { codepoint = 0x2F8FD, canonicalCombiningClass = 0, canonicalDecomposition = [0x6CCD] }
  , UnicodeDataRow { codepoint = 0x2F8FE, canonicalCombiningClass = 0, canonicalDecomposition = [0x6C67] }
  , UnicodeDataRow { codepoint = 0x2F8FF, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D16] }
  , UnicodeDataRow { codepoint = 0x2F900, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D3E] }
  , UnicodeDataRow { codepoint = 0x2F901, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D77] }
  , UnicodeDataRow { codepoint = 0x2F902, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D41] }
  , UnicodeDataRow { codepoint = 0x2F903, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D69] }
  , UnicodeDataRow { codepoint = 0x2F904, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D78] }
  , UnicodeDataRow { codepoint = 0x2F905, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D85] }
  , UnicodeDataRow { codepoint = 0x2F906, canonicalCombiningClass = 0, canonicalDecomposition = [0x23D1E] }
  , UnicodeDataRow { codepoint = 0x2F907, canonicalCombiningClass = 0, canonicalDecomposition = [0x6D34] }
  , UnicodeDataRow { codepoint = 0x2F908, canonicalCombiningClass = 0, canonicalDecomposition = [0x6E2F] }
  , UnicodeDataRow { codepoint = 0x2F909, canonicalCombiningClass = 0, canonicalDecomposition = [0x6E6E] }
  , UnicodeDataRow { codepoint = 0x2F90A, canonicalCombiningClass = 0, canonicalDecomposition = [0x3D33] }
  , UnicodeDataRow { codepoint = 0x2F90B, canonicalCombiningClass = 0, canonicalDecomposition = [0x6ECB] }
  , UnicodeDataRow { codepoint = 0x2F90C, canonicalCombiningClass = 0, canonicalDecomposition = [0x6EC7] }
  , UnicodeDataRow { codepoint = 0x2F90D, canonicalCombiningClass = 0, canonicalDecomposition = [0x23ED1] }
  , UnicodeDataRow { codepoint = 0x2F90E, canonicalCombiningClass = 0, canonicalDecomposition = [0x6DF9] }
  , UnicodeDataRow { codepoint = 0x2F90F, canonicalCombiningClass = 0, canonicalDecomposition = [0x6F6E] }
  , UnicodeDataRow { codepoint = 0x2F910, canonicalCombiningClass = 0, canonicalDecomposition = [0x23F5E] }
  , UnicodeDataRow { codepoint = 0x2F911, canonicalCombiningClass = 0, canonicalDecomposition = [0x23F8E] }
  , UnicodeDataRow { codepoint = 0x2F912, canonicalCombiningClass = 0, canonicalDecomposition = [0x6FC6] }
  , UnicodeDataRow { codepoint = 0x2F913, canonicalCombiningClass = 0, canonicalDecomposition = [0x7039] }
  , UnicodeDataRow { codepoint = 0x2F914, canonicalCombiningClass = 0, canonicalDecomposition = [0x701E] }
  , UnicodeDataRow { codepoint = 0x2F915, canonicalCombiningClass = 0, canonicalDecomposition = [0x701B] }
  , UnicodeDataRow { codepoint = 0x2F916, canonicalCombiningClass = 0, canonicalDecomposition = [0x3D96] }
  , UnicodeDataRow { codepoint = 0x2F917, canonicalCombiningClass = 0, canonicalDecomposition = [0x704A] }
  , UnicodeDataRow { codepoint = 0x2F918, canonicalCombiningClass = 0, canonicalDecomposition = [0x707D] }
  , UnicodeDataRow { codepoint = 0x2F919, canonicalCombiningClass = 0, canonicalDecomposition = [0x7077] }
  , UnicodeDataRow { codepoint = 0x2F91A, canonicalCombiningClass = 0, canonicalDecomposition = [0x70AD] }
  , UnicodeDataRow { codepoint = 0x2F91B, canonicalCombiningClass = 0, canonicalDecomposition = [0x20525] }
  , UnicodeDataRow { codepoint = 0x2F91C, canonicalCombiningClass = 0, canonicalDecomposition = [0x7145] }
  , UnicodeDataRow { codepoint = 0x2F91D, canonicalCombiningClass = 0, canonicalDecomposition = [0x24263] }
  , UnicodeDataRow { codepoint = 0x2F91E, canonicalCombiningClass = 0, canonicalDecomposition = [0x719C] }
  , UnicodeDataRow { codepoint = 0x2F91F, canonicalCombiningClass = 0, canonicalDecomposition = [0x243AB] }
  , UnicodeDataRow { codepoint = 0x2F920, canonicalCombiningClass = 0, canonicalDecomposition = [0x7228] }
  , UnicodeDataRow { codepoint = 0x2F921, canonicalCombiningClass = 0, canonicalDecomposition = [0x7235] }
  , UnicodeDataRow { codepoint = 0x2F922, canonicalCombiningClass = 0, canonicalDecomposition = [0x7250] }
  , UnicodeDataRow { codepoint = 0x2F923, canonicalCombiningClass = 0, canonicalDecomposition = [0x24608] }
  , UnicodeDataRow { codepoint = 0x2F924, canonicalCombiningClass = 0, canonicalDecomposition = [0x7280] }
  , UnicodeDataRow { codepoint = 0x2F925, canonicalCombiningClass = 0, canonicalDecomposition = [0x7295] }
  , UnicodeDataRow { codepoint = 0x2F926, canonicalCombiningClass = 0, canonicalDecomposition = [0x24735] }
  , UnicodeDataRow { codepoint = 0x2F927, canonicalCombiningClass = 0, canonicalDecomposition = [0x24814] }
  , UnicodeDataRow { codepoint = 0x2F928, canonicalCombiningClass = 0, canonicalDecomposition = [0x737A] }
  , UnicodeDataRow { codepoint = 0x2F929, canonicalCombiningClass = 0, canonicalDecomposition = [0x738B] }
  , UnicodeDataRow { codepoint = 0x2F92A, canonicalCombiningClass = 0, canonicalDecomposition = [0x3EAC] }
  , UnicodeDataRow { codepoint = 0x2F92B, canonicalCombiningClass = 0, canonicalDecomposition = [0x73A5] }
  , UnicodeDataRow { codepoint = 0x2F92C, canonicalCombiningClass = 0, canonicalDecomposition = [0x3EB8] }
  , UnicodeDataRow { codepoint = 0x2F92D, canonicalCombiningClass = 0, canonicalDecomposition = [0x3EB8] }
  , UnicodeDataRow { codepoint = 0x2F92E, canonicalCombiningClass = 0, canonicalDecomposition = [0x7447] }
  , UnicodeDataRow { codepoint = 0x2F92F, canonicalCombiningClass = 0, canonicalDecomposition = [0x745C] }
  , UnicodeDataRow { codepoint = 0x2F930, canonicalCombiningClass = 0, canonicalDecomposition = [0x7471] }
  , UnicodeDataRow { codepoint = 0x2F931, canonicalCombiningClass = 0, canonicalDecomposition = [0x7485] }
  , UnicodeDataRow { codepoint = 0x2F932, canonicalCombiningClass = 0, canonicalDecomposition = [0x74CA] }
  , UnicodeDataRow { codepoint = 0x2F933, canonicalCombiningClass = 0, canonicalDecomposition = [0x3F1B] }
  , UnicodeDataRow { codepoint = 0x2F934, canonicalCombiningClass = 0, canonicalDecomposition = [0x7524] }
  , UnicodeDataRow { codepoint = 0x2F935, canonicalCombiningClass = 0, canonicalDecomposition = [0x24C36] }
  , UnicodeDataRow { codepoint = 0x2F936, canonicalCombiningClass = 0, canonicalDecomposition = [0x753E] }
  , UnicodeDataRow { codepoint = 0x2F937, canonicalCombiningClass = 0, canonicalDecomposition = [0x24C92] }
  , UnicodeDataRow { codepoint = 0x2F938, canonicalCombiningClass = 0, canonicalDecomposition = [0x7570] }
  , UnicodeDataRow { codepoint = 0x2F939, canonicalCombiningClass = 0, canonicalDecomposition = [0x2219F] }
  , UnicodeDataRow { codepoint = 0x2F93A, canonicalCombiningClass = 0, canonicalDecomposition = [0x7610] }
  , UnicodeDataRow { codepoint = 0x2F93B, canonicalCombiningClass = 0, canonicalDecomposition = [0x24FA1] }
  , UnicodeDataRow { codepoint = 0x2F93C, canonicalCombiningClass = 0, canonicalDecomposition = [0x24FB8] }
  , UnicodeDataRow { codepoint = 0x2F93D, canonicalCombiningClass = 0, canonicalDecomposition = [0x25044] }
  , UnicodeDataRow { codepoint = 0x2F93E, canonicalCombiningClass = 0, canonicalDecomposition = [0x3FFC] }
  , UnicodeDataRow { codepoint = 0x2F93F, canonicalCombiningClass = 0, canonicalDecomposition = [0x4008] }
  , UnicodeDataRow { codepoint = 0x2F940, canonicalCombiningClass = 0, canonicalDecomposition = [0x76F4] }
  , UnicodeDataRow { codepoint = 0x2F941, canonicalCombiningClass = 0, canonicalDecomposition = [0x250F3] }
  , UnicodeDataRow { codepoint = 0x2F942, canonicalCombiningClass = 0, canonicalDecomposition = [0x250F2] }
  , UnicodeDataRow { codepoint = 0x2F943, canonicalCombiningClass = 0, canonicalDecomposition = [0x25119] }
  , UnicodeDataRow { codepoint = 0x2F944, canonicalCombiningClass = 0, canonicalDecomposition = [0x25133] }
  , UnicodeDataRow { codepoint = 0x2F945, canonicalCombiningClass = 0, canonicalDecomposition = [0x771E] }
  , UnicodeDataRow { codepoint = 0x2F946, canonicalCombiningClass = 0, canonicalDecomposition = [0x771F] }
  , UnicodeDataRow { codepoint = 0x2F947, canonicalCombiningClass = 0, canonicalDecomposition = [0x771F] }
  , UnicodeDataRow { codepoint = 0x2F948, canonicalCombiningClass = 0, canonicalDecomposition = [0x774A] }
  , UnicodeDataRow { codepoint = 0x2F949, canonicalCombiningClass = 0, canonicalDecomposition = [0x4039] }
  , UnicodeDataRow { codepoint = 0x2F94A, canonicalCombiningClass = 0, canonicalDecomposition = [0x778B] }
  , UnicodeDataRow { codepoint = 0x2F94B, canonicalCombiningClass = 0, canonicalDecomposition = [0x4046] }
  , UnicodeDataRow { codepoint = 0x2F94C, canonicalCombiningClass = 0, canonicalDecomposition = [0x4096] }
  , UnicodeDataRow { codepoint = 0x2F94D, canonicalCombiningClass = 0, canonicalDecomposition = [0x2541D] }
  , UnicodeDataRow { codepoint = 0x2F94E, canonicalCombiningClass = 0, canonicalDecomposition = [0x784E] }
  , UnicodeDataRow { codepoint = 0x2F94F, canonicalCombiningClass = 0, canonicalDecomposition = [0x788C] }
  , UnicodeDataRow { codepoint = 0x2F950, canonicalCombiningClass = 0, canonicalDecomposition = [0x78CC] }
  , UnicodeDataRow { codepoint = 0x2F951, canonicalCombiningClass = 0, canonicalDecomposition = [0x40E3] }
  , UnicodeDataRow { codepoint = 0x2F952, canonicalCombiningClass = 0, canonicalDecomposition = [0x25626] }
  , UnicodeDataRow { codepoint = 0x2F953, canonicalCombiningClass = 0, canonicalDecomposition = [0x7956] }
  , UnicodeDataRow { codepoint = 0x2F954, canonicalCombiningClass = 0, canonicalDecomposition = [0x2569A] }
  , UnicodeDataRow { codepoint = 0x2F955, canonicalCombiningClass = 0, canonicalDecomposition = [0x256C5] }
  , UnicodeDataRow { codepoint = 0x2F956, canonicalCombiningClass = 0, canonicalDecomposition = [0x798F] }
  , UnicodeDataRow { codepoint = 0x2F957, canonicalCombiningClass = 0, canonicalDecomposition = [0x79EB] }
  , UnicodeDataRow { codepoint = 0x2F958, canonicalCombiningClass = 0, canonicalDecomposition = [0x412F] }
  , UnicodeDataRow { codepoint = 0x2F959, canonicalCombiningClass = 0, canonicalDecomposition = [0x7A40] }
  , UnicodeDataRow { codepoint = 0x2F95A, canonicalCombiningClass = 0, canonicalDecomposition = [0x7A4A] }
  , UnicodeDataRow { codepoint = 0x2F95B, canonicalCombiningClass = 0, canonicalDecomposition = [0x7A4F] }
  , UnicodeDataRow { codepoint = 0x2F95C, canonicalCombiningClass = 0, canonicalDecomposition = [0x2597C] }
  , UnicodeDataRow { codepoint = 0x2F95D, canonicalCombiningClass = 0, canonicalDecomposition = [0x25AA7] }
  , UnicodeDataRow { codepoint = 0x2F95E, canonicalCombiningClass = 0, canonicalDecomposition = [0x25AA7] }
  , UnicodeDataRow { codepoint = 0x2F95F, canonicalCombiningClass = 0, canonicalDecomposition = [0x7AEE] }
  , UnicodeDataRow { codepoint = 0x2F960, canonicalCombiningClass = 0, canonicalDecomposition = [0x4202] }
  , UnicodeDataRow { codepoint = 0x2F961, canonicalCombiningClass = 0, canonicalDecomposition = [0x25BAB] }
  , UnicodeDataRow { codepoint = 0x2F962, canonicalCombiningClass = 0, canonicalDecomposition = [0x7BC6] }
  , UnicodeDataRow { codepoint = 0x2F963, canonicalCombiningClass = 0, canonicalDecomposition = [0x7BC9] }
  , UnicodeDataRow { codepoint = 0x2F964, canonicalCombiningClass = 0, canonicalDecomposition = [0x4227] }
  , UnicodeDataRow { codepoint = 0x2F965, canonicalCombiningClass = 0, canonicalDecomposition = [0x25C80] }
  , UnicodeDataRow { codepoint = 0x2F966, canonicalCombiningClass = 0, canonicalDecomposition = [0x7CD2] }
  , UnicodeDataRow { codepoint = 0x2F967, canonicalCombiningClass = 0, canonicalDecomposition = [0x42A0] }
  , UnicodeDataRow { codepoint = 0x2F968, canonicalCombiningClass = 0, canonicalDecomposition = [0x7CE8] }
  , UnicodeDataRow { codepoint = 0x2F969, canonicalCombiningClass = 0, canonicalDecomposition = [0x7CE3] }
  , UnicodeDataRow { codepoint = 0x2F96A, canonicalCombiningClass = 0, canonicalDecomposition = [0x7D00] }
  , UnicodeDataRow { codepoint = 0x2F96B, canonicalCombiningClass = 0, canonicalDecomposition = [0x25F86] }
  , UnicodeDataRow { codepoint = 0x2F96C, canonicalCombiningClass = 0, canonicalDecomposition = [0x7D63] }
  , UnicodeDataRow { codepoint = 0x2F96D, canonicalCombiningClass = 0, canonicalDecomposition = [0x4301] }
  , UnicodeDataRow { codepoint = 0x2F96E, canonicalCombiningClass = 0, canonicalDecomposition = [0x7DC7] }
  , UnicodeDataRow { codepoint = 0x2F96F, canonicalCombiningClass = 0, canonicalDecomposition = [0x7E02] }
  , UnicodeDataRow { codepoint = 0x2F970, canonicalCombiningClass = 0, canonicalDecomposition = [0x7E45] }
  , UnicodeDataRow { codepoint = 0x2F971, canonicalCombiningClass = 0, canonicalDecomposition = [0x4334] }
  , UnicodeDataRow { codepoint = 0x2F972, canonicalCombiningClass = 0, canonicalDecomposition = [0x26228] }
  , UnicodeDataRow { codepoint = 0x2F973, canonicalCombiningClass = 0, canonicalDecomposition = [0x26247] }
  , UnicodeDataRow { codepoint = 0x2F974, canonicalCombiningClass = 0, canonicalDecomposition = [0x4359] }
  , UnicodeDataRow { codepoint = 0x2F975, canonicalCombiningClass = 0, canonicalDecomposition = [0x262D9] }
  , UnicodeDataRow { codepoint = 0x2F976, canonicalCombiningClass = 0, canonicalDecomposition = [0x7F7A] }
  , UnicodeDataRow { codepoint = 0x2F977, canonicalCombiningClass = 0, canonicalDecomposition = [0x2633E] }
  , UnicodeDataRow { codepoint = 0x2F978, canonicalCombiningClass = 0, canonicalDecomposition = [0x7F95] }
  , UnicodeDataRow { codepoint = 0x2F979, canonicalCombiningClass = 0, canonicalDecomposition = [0x7FFA] }
  , UnicodeDataRow { codepoint = 0x2F97A, canonicalCombiningClass = 0, canonicalDecomposition = [0x8005] }
  , UnicodeDataRow { codepoint = 0x2F97B, canonicalCombiningClass = 0, canonicalDecomposition = [0x264DA] }
  , UnicodeDataRow { codepoint = 0x2F97C, canonicalCombiningClass = 0, canonicalDecomposition = [0x26523] }
  , UnicodeDataRow { codepoint = 0x2F97D, canonicalCombiningClass = 0, canonicalDecomposition = [0x8060] }
  , UnicodeDataRow { codepoint = 0x2F97E, canonicalCombiningClass = 0, canonicalDecomposition = [0x265A8] }
  , UnicodeDataRow { codepoint = 0x2F97F, canonicalCombiningClass = 0, canonicalDecomposition = [0x8070] }
  , UnicodeDataRow { codepoint = 0x2F980, canonicalCombiningClass = 0, canonicalDecomposition = [0x2335F] }
  , UnicodeDataRow { codepoint = 0x2F981, canonicalCombiningClass = 0, canonicalDecomposition = [0x43D5] }
  , UnicodeDataRow { codepoint = 0x2F982, canonicalCombiningClass = 0, canonicalDecomposition = [0x80B2] }
  , UnicodeDataRow { codepoint = 0x2F983, canonicalCombiningClass = 0, canonicalDecomposition = [0x8103] }
  , UnicodeDataRow { codepoint = 0x2F984, canonicalCombiningClass = 0, canonicalDecomposition = [0x440B] }
  , UnicodeDataRow { codepoint = 0x2F985, canonicalCombiningClass = 0, canonicalDecomposition = [0x813E] }
  , UnicodeDataRow { codepoint = 0x2F986, canonicalCombiningClass = 0, canonicalDecomposition = [0x5AB5] }
  , UnicodeDataRow { codepoint = 0x2F987, canonicalCombiningClass = 0, canonicalDecomposition = [0x267A7] }
  , UnicodeDataRow { codepoint = 0x2F988, canonicalCombiningClass = 0, canonicalDecomposition = [0x267B5] }
  , UnicodeDataRow { codepoint = 0x2F989, canonicalCombiningClass = 0, canonicalDecomposition = [0x23393] }
  , UnicodeDataRow { codepoint = 0x2F98A, canonicalCombiningClass = 0, canonicalDecomposition = [0x2339C] }
  , UnicodeDataRow { codepoint = 0x2F98B, canonicalCombiningClass = 0, canonicalDecomposition = [0x8201] }
  , UnicodeDataRow { codepoint = 0x2F98C, canonicalCombiningClass = 0, canonicalDecomposition = [0x8204] }
  , UnicodeDataRow { codepoint = 0x2F98D, canonicalCombiningClass = 0, canonicalDecomposition = [0x8F9E] }
  , UnicodeDataRow { codepoint = 0x2F98E, canonicalCombiningClass = 0, canonicalDecomposition = [0x446B] }
  , UnicodeDataRow { codepoint = 0x2F98F, canonicalCombiningClass = 0, canonicalDecomposition = [0x8291] }
  , UnicodeDataRow { codepoint = 0x2F990, canonicalCombiningClass = 0, canonicalDecomposition = [0x828B] }
  , UnicodeDataRow { codepoint = 0x2F991, canonicalCombiningClass = 0, canonicalDecomposition = [0x829D] }
  , UnicodeDataRow { codepoint = 0x2F992, canonicalCombiningClass = 0, canonicalDecomposition = [0x52B3] }
  , UnicodeDataRow { codepoint = 0x2F993, canonicalCombiningClass = 0, canonicalDecomposition = [0x82B1] }
  , UnicodeDataRow { codepoint = 0x2F994, canonicalCombiningClass = 0, canonicalDecomposition = [0x82B3] }
  , UnicodeDataRow { codepoint = 0x2F995, canonicalCombiningClass = 0, canonicalDecomposition = [0x82BD] }
  , UnicodeDataRow { codepoint = 0x2F996, canonicalCombiningClass = 0, canonicalDecomposition = [0x82E6] }
  , UnicodeDataRow { codepoint = 0x2F997, canonicalCombiningClass = 0, canonicalDecomposition = [0x26B3C] }
  , UnicodeDataRow { codepoint = 0x2F998, canonicalCombiningClass = 0, canonicalDecomposition = [0x82E5] }
  , UnicodeDataRow { codepoint = 0x2F999, canonicalCombiningClass = 0, canonicalDecomposition = [0x831D] }
  , UnicodeDataRow { codepoint = 0x2F99A, canonicalCombiningClass = 0, canonicalDecomposition = [0x8363] }
  , UnicodeDataRow { codepoint = 0x2F99B, canonicalCombiningClass = 0, canonicalDecomposition = [0x83AD] }
  , UnicodeDataRow { codepoint = 0x2F99C, canonicalCombiningClass = 0, canonicalDecomposition = [0x8323] }
  , UnicodeDataRow { codepoint = 0x2F99D, canonicalCombiningClass = 0, canonicalDecomposition = [0x83BD] }
  , UnicodeDataRow { codepoint = 0x2F99E, canonicalCombiningClass = 0, canonicalDecomposition = [0x83E7] }
  , UnicodeDataRow { codepoint = 0x2F99F, canonicalCombiningClass = 0, canonicalDecomposition = [0x8457] }
  , UnicodeDataRow { codepoint = 0x2F9A0, canonicalCombiningClass = 0, canonicalDecomposition = [0x8353] }
  , UnicodeDataRow { codepoint = 0x2F9A1, canonicalCombiningClass = 0, canonicalDecomposition = [0x83CA] }
  , UnicodeDataRow { codepoint = 0x2F9A2, canonicalCombiningClass = 0, canonicalDecomposition = [0x83CC] }
  , UnicodeDataRow { codepoint = 0x2F9A3, canonicalCombiningClass = 0, canonicalDecomposition = [0x83DC] }
  , UnicodeDataRow { codepoint = 0x2F9A4, canonicalCombiningClass = 0, canonicalDecomposition = [0x26C36] }
  , UnicodeDataRow { codepoint = 0x2F9A5, canonicalCombiningClass = 0, canonicalDecomposition = [0x26D6B] }
  , UnicodeDataRow { codepoint = 0x2F9A6, canonicalCombiningClass = 0, canonicalDecomposition = [0x26CD5] }
  , UnicodeDataRow { codepoint = 0x2F9A7, canonicalCombiningClass = 0, canonicalDecomposition = [0x452B] }
  , UnicodeDataRow { codepoint = 0x2F9A8, canonicalCombiningClass = 0, canonicalDecomposition = [0x84F1] }
  , UnicodeDataRow { codepoint = 0x2F9A9, canonicalCombiningClass = 0, canonicalDecomposition = [0x84F3] }
  , UnicodeDataRow { codepoint = 0x2F9AA, canonicalCombiningClass = 0, canonicalDecomposition = [0x8516] }
  , UnicodeDataRow { codepoint = 0x2F9AB, canonicalCombiningClass = 0, canonicalDecomposition = [0x273CA] }
  , UnicodeDataRow { codepoint = 0x2F9AC, canonicalCombiningClass = 0, canonicalDecomposition = [0x8564] }
  , UnicodeDataRow { codepoint = 0x2F9AD, canonicalCombiningClass = 0, canonicalDecomposition = [0x26F2C] }
  , UnicodeDataRow { codepoint = 0x2F9AE, canonicalCombiningClass = 0, canonicalDecomposition = [0x455D] }
  , UnicodeDataRow { codepoint = 0x2F9AF, canonicalCombiningClass = 0, canonicalDecomposition = [0x4561] }
  , UnicodeDataRow { codepoint = 0x2F9B0, canonicalCombiningClass = 0, canonicalDecomposition = [0x26FB1] }
  , UnicodeDataRow { codepoint = 0x2F9B1, canonicalCombiningClass = 0, canonicalDecomposition = [0x270D2] }
  , UnicodeDataRow { codepoint = 0x2F9B2, canonicalCombiningClass = 0, canonicalDecomposition = [0x456B] }
  , UnicodeDataRow { codepoint = 0x2F9B3, canonicalCombiningClass = 0, canonicalDecomposition = [0x8650] }
  , UnicodeDataRow { codepoint = 0x2F9B4, canonicalCombiningClass = 0, canonicalDecomposition = [0x865C] }
  , UnicodeDataRow { codepoint = 0x2F9B5, canonicalCombiningClass = 0, canonicalDecomposition = [0x8667] }
  , UnicodeDataRow { codepoint = 0x2F9B6, canonicalCombiningClass = 0, canonicalDecomposition = [0x8669] }
  , UnicodeDataRow { codepoint = 0x2F9B7, canonicalCombiningClass = 0, canonicalDecomposition = [0x86A9] }
  , UnicodeDataRow { codepoint = 0x2F9B8, canonicalCombiningClass = 0, canonicalDecomposition = [0x8688] }
  , UnicodeDataRow { codepoint = 0x2F9B9, canonicalCombiningClass = 0, canonicalDecomposition = [0x870E] }
  , UnicodeDataRow { codepoint = 0x2F9BA, canonicalCombiningClass = 0, canonicalDecomposition = [0x86E2] }
  , UnicodeDataRow { codepoint = 0x2F9BB, canonicalCombiningClass = 0, canonicalDecomposition = [0x8779] }
  , UnicodeDataRow { codepoint = 0x2F9BC, canonicalCombiningClass = 0, canonicalDecomposition = [0x8728] }
  , UnicodeDataRow { codepoint = 0x2F9BD, canonicalCombiningClass = 0, canonicalDecomposition = [0x876B] }
  , UnicodeDataRow { codepoint = 0x2F9BE, canonicalCombiningClass = 0, canonicalDecomposition = [0x8786] }
  , UnicodeDataRow { codepoint = 0x2F9BF, canonicalCombiningClass = 0, canonicalDecomposition = [0x45D7] }
  , UnicodeDataRow { codepoint = 0x2F9C0, canonicalCombiningClass = 0, canonicalDecomposition = [0x87E1] }
  , UnicodeDataRow { codepoint = 0x2F9C1, canonicalCombiningClass = 0, canonicalDecomposition = [0x8801] }
  , UnicodeDataRow { codepoint = 0x2F9C2, canonicalCombiningClass = 0, canonicalDecomposition = [0x45F9] }
  , UnicodeDataRow { codepoint = 0x2F9C3, canonicalCombiningClass = 0, canonicalDecomposition = [0x8860] }
  , UnicodeDataRow { codepoint = 0x2F9C4, canonicalCombiningClass = 0, canonicalDecomposition = [0x8863] }
  , UnicodeDataRow { codepoint = 0x2F9C5, canonicalCombiningClass = 0, canonicalDecomposition = [0x27667] }
  , UnicodeDataRow { codepoint = 0x2F9C6, canonicalCombiningClass = 0, canonicalDecomposition = [0x88D7] }
  , UnicodeDataRow { codepoint = 0x2F9C7, canonicalCombiningClass = 0, canonicalDecomposition = [0x88DE] }
  , UnicodeDataRow { codepoint = 0x2F9C8, canonicalCombiningClass = 0, canonicalDecomposition = [0x4635] }
  , UnicodeDataRow { codepoint = 0x2F9C9, canonicalCombiningClass = 0, canonicalDecomposition = [0x88FA] }
  , UnicodeDataRow { codepoint = 0x2F9CA, canonicalCombiningClass = 0, canonicalDecomposition = [0x34BB] }
  , UnicodeDataRow { codepoint = 0x2F9CB, canonicalCombiningClass = 0, canonicalDecomposition = [0x278AE] }
  , UnicodeDataRow { codepoint = 0x2F9CC, canonicalCombiningClass = 0, canonicalDecomposition = [0x27966] }
  , UnicodeDataRow { codepoint = 0x2F9CD, canonicalCombiningClass = 0, canonicalDecomposition = [0x46BE] }
  , UnicodeDataRow { codepoint = 0x2F9CE, canonicalCombiningClass = 0, canonicalDecomposition = [0x46C7] }
  , UnicodeDataRow { codepoint = 0x2F9CF, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AA0] }
  , UnicodeDataRow { codepoint = 0x2F9D0, canonicalCombiningClass = 0, canonicalDecomposition = [0x8AED] }
  , UnicodeDataRow { codepoint = 0x2F9D1, canonicalCombiningClass = 0, canonicalDecomposition = [0x8B8A] }
  , UnicodeDataRow { codepoint = 0x2F9D2, canonicalCombiningClass = 0, canonicalDecomposition = [0x8C55] }
  , UnicodeDataRow { codepoint = 0x2F9D3, canonicalCombiningClass = 0, canonicalDecomposition = [0x27CA8] }
  , UnicodeDataRow { codepoint = 0x2F9D4, canonicalCombiningClass = 0, canonicalDecomposition = [0x8CAB] }
  , UnicodeDataRow { codepoint = 0x2F9D5, canonicalCombiningClass = 0, canonicalDecomposition = [0x8CC1] }
  , UnicodeDataRow { codepoint = 0x2F9D6, canonicalCombiningClass = 0, canonicalDecomposition = [0x8D1B] }
  , UnicodeDataRow { codepoint = 0x2F9D7, canonicalCombiningClass = 0, canonicalDecomposition = [0x8D77] }
  , UnicodeDataRow { codepoint = 0x2F9D8, canonicalCombiningClass = 0, canonicalDecomposition = [0x27F2F] }
  , UnicodeDataRow { codepoint = 0x2F9D9, canonicalCombiningClass = 0, canonicalDecomposition = [0x20804] }
  , UnicodeDataRow { codepoint = 0x2F9DA, canonicalCombiningClass = 0, canonicalDecomposition = [0x8DCB] }
  , UnicodeDataRow { codepoint = 0x2F9DB, canonicalCombiningClass = 0, canonicalDecomposition = [0x8DBC] }
  , UnicodeDataRow { codepoint = 0x2F9DC, canonicalCombiningClass = 0, canonicalDecomposition = [0x8DF0] }
  , UnicodeDataRow { codepoint = 0x2F9DD, canonicalCombiningClass = 0, canonicalDecomposition = [0x208DE] }
  , UnicodeDataRow { codepoint = 0x2F9DE, canonicalCombiningClass = 0, canonicalDecomposition = [0x8ED4] }
  , UnicodeDataRow { codepoint = 0x2F9DF, canonicalCombiningClass = 0, canonicalDecomposition = [0x8F38] }
  , UnicodeDataRow { codepoint = 0x2F9E0, canonicalCombiningClass = 0, canonicalDecomposition = [0x285D2] }
  , UnicodeDataRow { codepoint = 0x2F9E1, canonicalCombiningClass = 0, canonicalDecomposition = [0x285ED] }
  , UnicodeDataRow { codepoint = 0x2F9E2, canonicalCombiningClass = 0, canonicalDecomposition = [0x9094] }
  , UnicodeDataRow { codepoint = 0x2F9E3, canonicalCombiningClass = 0, canonicalDecomposition = [0x90F1] }
  , UnicodeDataRow { codepoint = 0x2F9E4, canonicalCombiningClass = 0, canonicalDecomposition = [0x9111] }
  , UnicodeDataRow { codepoint = 0x2F9E5, canonicalCombiningClass = 0, canonicalDecomposition = [0x2872E] }
  , UnicodeDataRow { codepoint = 0x2F9E6, canonicalCombiningClass = 0, canonicalDecomposition = [0x911B] }
  , UnicodeDataRow { codepoint = 0x2F9E7, canonicalCombiningClass = 0, canonicalDecomposition = [0x9238] }
  , UnicodeDataRow { codepoint = 0x2F9E8, canonicalCombiningClass = 0, canonicalDecomposition = [0x92D7] }
  , UnicodeDataRow { codepoint = 0x2F9E9, canonicalCombiningClass = 0, canonicalDecomposition = [0x92D8] }
  , UnicodeDataRow { codepoint = 0x2F9EA, canonicalCombiningClass = 0, canonicalDecomposition = [0x927C] }
  , UnicodeDataRow { codepoint = 0x2F9EB, canonicalCombiningClass = 0, canonicalDecomposition = [0x93F9] }
  , UnicodeDataRow { codepoint = 0x2F9EC, canonicalCombiningClass = 0, canonicalDecomposition = [0x9415] }
  , UnicodeDataRow { codepoint = 0x2F9ED, canonicalCombiningClass = 0, canonicalDecomposition = [0x28BFA] }
  , UnicodeDataRow { codepoint = 0x2F9EE, canonicalCombiningClass = 0, canonicalDecomposition = [0x958B] }
  , UnicodeDataRow { codepoint = 0x2F9EF, canonicalCombiningClass = 0, canonicalDecomposition = [0x4995] }
  , UnicodeDataRow { codepoint = 0x2F9F0, canonicalCombiningClass = 0, canonicalDecomposition = [0x95B7] }
  , UnicodeDataRow { codepoint = 0x2F9F1, canonicalCombiningClass = 0, canonicalDecomposition = [0x28D77] }
  , UnicodeDataRow { codepoint = 0x2F9F2, canonicalCombiningClass = 0, canonicalDecomposition = [0x49E6] }
  , UnicodeDataRow { codepoint = 0x2F9F3, canonicalCombiningClass = 0, canonicalDecomposition = [0x96C3] }
  , UnicodeDataRow { codepoint = 0x2F9F4, canonicalCombiningClass = 0, canonicalDecomposition = [0x5DB2] }
  , UnicodeDataRow { codepoint = 0x2F9F5, canonicalCombiningClass = 0, canonicalDecomposition = [0x9723] }
  , UnicodeDataRow { codepoint = 0x2F9F6, canonicalCombiningClass = 0, canonicalDecomposition = [0x29145] }
  , UnicodeDataRow { codepoint = 0x2F9F7, canonicalCombiningClass = 0, canonicalDecomposition = [0x2921A] }
  , UnicodeDataRow { codepoint = 0x2F9F8, canonicalCombiningClass = 0, canonicalDecomposition = [0x4A6E] }
  , UnicodeDataRow { codepoint = 0x2F9F9, canonicalCombiningClass = 0, canonicalDecomposition = [0x4A76] }
  , UnicodeDataRow { codepoint = 0x2F9FA, canonicalCombiningClass = 0, canonicalDecomposition = [0x97E0] }
  , UnicodeDataRow { codepoint = 0x2F9FB, canonicalCombiningClass = 0, canonicalDecomposition = [0x2940A] }
  , UnicodeDataRow { codepoint = 0x2F9FC, canonicalCombiningClass = 0, canonicalDecomposition = [0x4AB2] }
  , UnicodeDataRow { codepoint = 0x2F9FD, canonicalCombiningClass = 0, canonicalDecomposition = [0x29496] }
  , UnicodeDataRow { codepoint = 0x2F9FE, canonicalCombiningClass = 0, canonicalDecomposition = [0x980B] }
  , UnicodeDataRow { codepoint = 0x2F9FF, canonicalCombiningClass = 0, canonicalDecomposition = [0x980B] }
  , UnicodeDataRow { codepoint = 0x2FA00, canonicalCombiningClass = 0, canonicalDecomposition = [0x9829] }
  , UnicodeDataRow { codepoint = 0x2FA01, canonicalCombiningClass = 0, canonicalDecomposition = [0x295B6] }
  , UnicodeDataRow { codepoint = 0x2FA02, canonicalCombiningClass = 0, canonicalDecomposition = [0x98E2] }
  , UnicodeDataRow { codepoint = 0x2FA03, canonicalCombiningClass = 0, canonicalDecomposition = [0x4B33] }
  , UnicodeDataRow { codepoint = 0x2FA04, canonicalCombiningClass = 0, canonicalDecomposition = [0x9929] }
  , UnicodeDataRow { codepoint = 0x2FA05, canonicalCombiningClass = 0, canonicalDecomposition = [0x99A7] }
  , UnicodeDataRow { codepoint = 0x2FA06, canonicalCombiningClass = 0, canonicalDecomposition = [0x99C2] }
  , UnicodeDataRow { codepoint = 0x2FA07, canonicalCombiningClass = 0, canonicalDecomposition = [0x99FE] }
  , UnicodeDataRow { codepoint = 0x2FA08, canonicalCombiningClass = 0, canonicalDecomposition = [0x4BCE] }
  , UnicodeDataRow { codepoint = 0x2FA09, canonicalCombiningClass = 0, canonicalDecomposition = [0x29B30] }
  , UnicodeDataRow { codepoint = 0x2FA0A, canonicalCombiningClass = 0, canonicalDecomposition = [0x9B12] }
  , UnicodeDataRow { codepoint = 0x2FA0B, canonicalCombiningClass = 0, canonicalDecomposition = [0x9C40] }
  , UnicodeDataRow { codepoint = 0x2FA0C, canonicalCombiningClass = 0, canonicalDecomposition = [0x9CFD] }
  , UnicodeDataRow { codepoint = 0x2FA0D, canonicalCombiningClass = 0, canonicalDecomposition = [0x4CCE] }
  , UnicodeDataRow { codepoint = 0x2FA0E, canonicalCombiningClass = 0, canonicalDecomposition = [0x4CED] }
  , UnicodeDataRow { codepoint = 0x2FA0F, canonicalCombiningClass = 0, canonicalDecomposition = [0x9D67] }
  , UnicodeDataRow { codepoint = 0x2FA10, canonicalCombiningClass = 0, canonicalDecomposition = [0x2A0CE] }
  , UnicodeDataRow { codepoint = 0x2FA11, canonicalCombiningClass = 0, canonicalDecomposition = [0x4CF8] }
  , UnicodeDataRow { codepoint = 0x2FA12, canonicalCombiningClass = 0, canonicalDecomposition = [0x2A105] }
  , UnicodeDataRow { codepoint = 0x2FA13, canonicalCombiningClass = 0, canonicalDecomposition = [0x2A20E] }
  , UnicodeDataRow { codepoint = 0x2FA14, canonicalCombiningClass = 0, canonicalDecomposition = [0x2A291] }
  , UnicodeDataRow { codepoint = 0x2FA15, canonicalCombiningClass = 0, canonicalDecomposition = [0x9EBB] }
  , UnicodeDataRow { codepoint = 0x2FA16, canonicalCombiningClass = 0, canonicalDecomposition = [0x4D56] }
  , UnicodeDataRow { codepoint = 0x2FA17, canonicalCombiningClass = 0, canonicalDecomposition = [0x9EF9] }
  , UnicodeDataRow { codepoint = 0x2FA18, canonicalCombiningClass = 0, canonicalDecomposition = [0x9EFE] }
  , UnicodeDataRow { codepoint = 0x2FA19, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F05] }
  , UnicodeDataRow { codepoint = 0x2FA1A, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F0F] }
  , UnicodeDataRow { codepoint = 0x2FA1B, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F16] }
  , UnicodeDataRow { codepoint = 0x2FA1C, canonicalCombiningClass = 0, canonicalDecomposition = [0x9F3B] }
  , UnicodeDataRow { codepoint = 0x2FA1D, canonicalCombiningClass = 0, canonicalDecomposition = [0x2A600] }
  ]
