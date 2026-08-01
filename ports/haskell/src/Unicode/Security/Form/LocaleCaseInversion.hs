{-|
Module      : Unicode.Security.Form.LocaleCaseInversion
Description : Locale-case-inversion detector (UAX #21 / Tier A2).

Haskell port of @Unicode.Security.Form.LocaleCaseInversion@ from
unicode-lean.

Detects inputs whose lowercase fold inverts across locales — the
homograph-via-locale attack (CVE-2007-6692, CVE-2021-30245, the Spotify
"İSTANBUL" / "iSTANBUL" incident class). One stage folds the input under the
default locale to compare against a stored credential while another folds it
under Turkish or Lithuanian; the two folds diverge and the attacker controls
which is used where.

Detection compares per-position 'lowerCodepoint' under each locale against the
default, rather than diffing whole-string @toLower@, because 'lowerCodepoint'
evaluates the SpecialCasing context predicates (After_I, More_Above,
Not_Before_Dot, After_Soft_Dotted, Final_Sigma) with the full surrounding
context — so a per-position diff is sound under the context-sensitive rules.
Turkish divergence takes priority over Lithuanian (SpecialCasing has no
@az@-only codepoint, so Turkish covers Azeri).
-}
module Unicode.Security.Form.LocaleCaseInversion
  ( Detection (Detection, detectionSub, detectionPositions)
  , detect
  ) where

import Unicode.Casing (Locale (Default, Lithuanian, Turkish), lowerCodepoint)

-- | One locale-case-inversion scan result: the divergent-locale sub-threat tag
-- (@Nothing@ when clear) and the first divergent input position.
data Detection = Detection
  { detectionSub       :: !(Maybe String)
  , detectionPositions :: ![Int]
  }
  deriving stock (Eq, Show)

-- | First input position whose 'lowerCodepoint' under @locale@ differs from the
-- default-locale result, with the codepoint there. @revPrefix@ carries the
-- already-processed codepoints nearest-first so each position reads its context.
firstLocaleDivergence :: Locale -> [Int] -> Maybe (Int, Int)
firstLocaleDivergence locale = go 0 []
  where
    go _index _revPrefix [] = Nothing
    go index revPrefix (cp : suffix)
      | lowerCodepoint Default revPrefix suffix cp
          /= lowerCodepoint locale revPrefix suffix cp = Just (index, cp)
      | otherwise = go (index + 1) (cp : revPrefix) suffix

-- | Detect an input whose lowercase fold inverts across locales. Turkish
-- divergence takes priority; Lithuanian is reached only when no Turkish
-- divergence is found.
detect :: [Int] -> Detection
detect input =
  case firstLocaleDivergence Turkish input of
    Just (pos, _cp) -> Detection (Just "TurkishCaseDivergence") [pos]
    Nothing ->
      case firstLocaleDivergence Lithuanian input of
        Just (pos, _cp) -> Detection (Just "LithuanianCaseDivergence") [pos]
        Nothing -> Detection Nothing []
