{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                                      // unicode // segmentation // line-break
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | @Unicode.Segmentation.LineBreak@ — UAX #14 default line breaking.
--
-- Where a line may break is a property of a sequence, not of a codepoint: the
-- answer at one boundary depends on the classes on both sides of it and on how
-- far back the last significant character sits. 'lineBreaks' therefore returns
-- one flag per boundary position rather than a predicate over codepoints.
--
-- Haskell mirror of the Lean @Unicode.Segmentation.LineBreak.lineBreaks@, rule
-- order and rule bodies as that file states them — LB2 through LB31 in UAX #14
-- R7's canonical order, first match winning, the trailing LB31 breaking every
-- otherwise-unmatched pair. Each guard carries the rule it implements.
--
-- Three mechanisms carry the context the rules read:
--
--   * LB1 is applied at lookup time by 'resolvedClass', which folds the
--     tailorable @AI@, @CJ@, @SA@, @SG@ and @XX@ into the algorithm's working
--     alphabet. @SA@ needs General_Category to choose between @CM@ and @AL@.
--   * LB9 — treat @X CM*@ / @X ZWJ*@ as @X@ — is realised through 'Snapshot',
--     whose fields hold the most recent class that was not @CM@ or @ZWJ@. LB10,
--     treating a leftover @CM@ or @ZWJ@ as @AL@, is the fallback taken when no
--     such class exists.
--   * The rules that name a third character — LB15c, LB15b, the LB25 bracket
--     and the fourth LB28a sub-rule — read the suffix beginning at the current
--     position, so a lookahead needs no index arithmetic and no partial access.
--
-- Two deliberate departures from the Lean, both because lemma forbids what the
-- Lean relies on. Positional reads there are @lits[i]!@ and @cps[i]!@; here
-- every read comes from a suffix the caller already holds, so the function is
-- total. And the Lean's @spSinceNoSp@ snapshot field is written by its fold and
-- read by no rule, so the mirror does not carry it.
module Unicode.Segmentation.LineBreak
    ( resolvedClass
    , lineBreaks
    , lineRuns
    ) where

import Unicode.Generated.DerivedGeneralCategory
    ( GeneralCategory
        ( GcLu, GcLl, GcLt, GcLm, GcLo, GcMn, GcMc, GcMe, GcNd, GcNl, GcNo
        , GcPc, GcPd, GcPs, GcPe, GcPi, GcPf, GcPo, GcSm, GcSc, GcSk, GcSo
        , GcZs, GcZl, GcZp, GcCc, GcCf, GcCs, GcCo, GcCn
        )
    )
import Unicode.Generated.EastAsianWidth
    ( EastAsianWidth (EawA, EawF, EawH, EawN, EawNa, EawW)
    )
import Unicode.Generated.LineBreakProperty
    ( LineBreakClass
        ( LbAI, LbAK, LbAL, LbAP, LbAS, LbB2, LbBA, LbBB, LbBK, LbCB, LbCJ
        , LbCL, LbCM, LbCP, LbCR, LbEB, LbEM, LbEX, LbGL, LbH2, LbH3, LbHH
        , LbHL, LbHY, LbID, LbIN, LbIS, LbJL, LbJT, LbJV, LbLF, LbNL, LbNS
        , LbNU, LbOP, LbPO, LbPR, LbQU, LbRI, LbSA, LbSG, LbSP, LbSY, LbVF
        , LbVI, LbWJ, LbXX, LbZW, LbZWJ
        )
    )
import Unicode.Property
    ( eastAsianWidthOf
    , generalCategoryOf
    , isEastAsianFullWide
    , lineBreakOf
    )
import Unicode.Segmentation.Grapheme (isExtPict)

-- ═════════════════════════════════════════════════════════════════════════════
--                                                          // lb1 // resolution
-- ═════════════════════════════════════════════════════════════════════════════

-- | The Line_Break class a codepoint carries once LB1 has tailored it.
--
-- @AI@, @SG@ and @XX@ resolve to @AL@; @CJ@ to @NS@; @SA@ to @CM@ when the
-- codepoint is a non-spacing or spacing combining mark and to @AL@ otherwise.
-- Every other class is already in the working alphabet.
resolvedClass :: Int -> LineBreakClass
resolvedClass codepoint =
    case lineBreakOf codepoint of
        LbAI -> LbAL
        LbCJ -> LbNS
        LbSG -> LbAL
        LbXX -> LbAL
        LbSA -> if isMarkCategory (generalCategoryOf codepoint)
                    then LbCM
                    else LbAL
        resolved -> resolved

-- | True iff the General_Category is one LB1 reads as a combining mark when it
-- resolves @SA@ — non-spacing or spacing combining. Enclosing marks are not
-- among them, matching the rule's own @{Mn, Mc}@ set.
isMarkCategory :: GeneralCategory -> Bool
isMarkCategory category =
    case category of
        GcMn -> True
        GcMc -> True
        GcMe -> False
        GcLu -> False
        GcLl -> False
        GcLt -> False
        GcLm -> False
        GcLo -> False
        GcNd -> False
        GcNl -> False
        GcNo -> False
        GcPc -> False
        GcPd -> False
        GcPs -> False
        GcPe -> False
        GcPi -> False
        GcPf -> False
        GcPo -> False
        GcSm -> False
        GcSc -> False
        GcSk -> False
        GcSo -> False
        GcZs -> False
        GcZl -> False
        GcZp -> False
        GcCc -> False
        GcCf -> False
        GcCs -> False
        GcCo -> False
        GcCn -> False

-- ═════════════════════════════════════════════════════════════════════════════
--                                                             // lb9 // context
-- ═════════════════════════════════════════════════════════════════════════════

-- | True iff LB9 absorbs this class into the character before it.
isCmZwj :: LineBreakClass -> Bool
isCmZwj cls = cls == LbCM || cls == LbZWJ

-- | True iff a preceding class blocks LB9's absorption, so a following @CM@ or
-- @ZWJ@ stands on its own and LB10 reads it as @AL@.
blocksAbsorb :: LineBreakClass -> Bool
blocksAbsorb cls =
    cls == LbBK || cls == LbCR || cls == LbLF
        || cls == LbNL || cls == LbSP || cls == LbZW

-- | The left-hand context a boundary decision reads: the classes and
-- codepoints of the most recent characters LB9 did not absorb, plus the three
-- running counters the rules keep.
data Snapshot = Snapshot
    { effPrev       :: !(Maybe LineBreakClass)
      -- ^ Class of the most recent character that was not @CM@ or @ZWJ@.
    , effPrevCp     :: !(Maybe Int)
      -- ^ Its codepoint — LB20a, LB21a and LB28a name U+2010 and U+25CC.
    , effPrevNoSp   :: !(Maybe LineBreakClass)
      -- ^ Class of the most recent character that was not @CM@, @ZWJ@ or @SP@.
    , effPrevPrev   :: !(Maybe LineBreakClass)
      -- ^ Class of the second most recent such character.
    , effPrevPrevCp :: !(Maybe Int)
      -- ^ Its codepoint.
    , inPiQuoteWindow :: !Bool
      -- ^ Whether an LB15a initial-punctuation quote window is open.
    , riRun         :: !Int
      -- ^ Length of the current regional-indicator run, for LB30a.
    , inNuChain     :: !Bool
      -- ^ Whether an LB25 numeric chain is open.
    }

initialSnapshot :: Snapshot
initialSnapshot = Snapshot
    { effPrev         = Nothing
    , effPrevCp       = Nothing
    , effPrevNoSp     = Nothing
    , effPrevPrev     = Nothing
    , effPrevPrevCp   = Nothing
    , inPiQuoteWindow = False
    , riRun           = 0
    , inNuChain       = False
    }

-- | Fold one character into the context. A character LB9 absorbs leaves the
-- context untouched, which is what makes the neighbours it records effective
-- rather than literal.
advance :: Snapshot -> (Int, LineBreakClass) -> Snapshot
advance snapshot (codepoint, cls)
    | isCmZwj effective = snapshot
    | otherwise = Snapshot
        { effPrev         = Just effective
        , effPrevCp       = Just codepoint
        , effPrevNoSp     =
            if effective == LbSP then effPrevNoSp snapshot else Just effective
        , effPrevPrev     = effPrev snapshot
        , effPrevPrevCp   = effPrevCp snapshot
        , inPiQuoteWindow = quoteWindow
        , riRun           = if effective == LbRI then riRun snapshot + 1 else 0
        , inNuChain       = numericChain
        }
  where
    effective
        | not (isCmZwj cls) = cls
        | otherwise =
            case effPrev snapshot of
                Nothing   -> LbAL
                Just prev -> if blocksAbsorb prev then LbAL else cls

    -- LB15a opens its window only where an initial-punctuation quote stands
    -- outside a word; a space carries an open window forward.
    quoteWindow
        | isPiQuote codepoint effective && leftContextOpens = True
        | effective == LbSP = inPiQuoteWindow snapshot
        | otherwise = False

    leftContextOpens =
        case effPrev snapshot of
            Nothing  -> True
            Just prev ->
                prev == LbBK || prev == LbCR || prev == LbLF || prev == LbNL
                    || prev == LbOP || prev == LbQU || prev == LbGL
                    || prev == LbSP || prev == LbZW

    numericChain
        | effective == LbNU = True
        | inNuChain snapshot
        , effective == LbSY || effective == LbIS || effective == LbCL
            || effective == LbCP || effective == LbPR = True
        | otherwise = False

-- ═════════════════════════════════════════════════════════════════════════════
--                                                       // quote // refinements
-- ═════════════════════════════════════════════════════════════════════════════

-- | True iff the class is @QU@ and the codepoint is initial punctuation, the
-- refinement LB15a reads.
isPiQuote :: Int -> LineBreakClass -> Bool
isPiQuote codepoint cls =
    cls == LbQU && generalCategoryOf codepoint == GcPi

-- | True iff the class is @QU@ and the codepoint is final punctuation, the
-- refinement LB15b reads.
isPfQuote :: Int -> LineBreakClass -> Bool
isPfQuote codepoint cls =
    cls == LbQU && generalCategoryOf codepoint == GcPf

-- | True iff the codepoint is U+2010 HYPHEN, which LB20a and LB21a name
-- explicitly because UCD 17.0 moved it from class @HY@ to class @HH@.
isHyphenU2010 :: Int -> Bool
isHyphenU2010 codepoint = codepoint == 0x2010

-- | True iff the codepoint counts as East Asian for LB19a's tailoring, which
-- treats @Ambiguous@ as East Asian alongside @Fullwidth@, @Wide@ and
-- @Halfwidth@. Wider than 'isEastAsianFullWide', which LB25 and LB30 read.
isEastAsianOrAmbiguous :: Int -> Bool
isEastAsianOrAmbiguous codepoint =
    case eastAsianWidthOf codepoint of
        EawF  -> True
        EawW  -> True
        EawH  -> True
        EawA  -> True
        EawN  -> False
        EawNa -> False

-- | True iff the effective class is present and one of the listed classes.
effIn :: Maybe LineBreakClass -> [LineBreakClass] -> Bool
effIn effective classes =
    case effective of
        Just cls -> cls `elem` classes
        Nothing  -> False

-- ═════════════════════════════════════════════════════════════════════════════
--                                                         // the // rule // set
-- ═════════════════════════════════════════════════════════════════════════════

-- | Whether a line break opportunity falls immediately before the head of
-- @suffix@, given the character before it and the context accumulated from
-- everything earlier.
--
-- @suffix@ begins at the position being decided, so its head is the current
-- character and its tail supplies every lookahead the rules take.
breaksBefore
    :: (Int, LineBreakClass)
    -> [(Int, LineBreakClass)]
    -> Snapshot
    -> Bool
breaksBefore (prevCp, prevCls) suffix snapshot =
    case suffix of
        [] -> True
        (currentCp, currentCls) : ahead -> decide currentCp currentCls ahead
  where
    decide currentCp currentCls ahead
        -- LB4
        | prevCls == LbBK = True
        -- LB5
        | prevCls == LbCR && currentCls == LbLF = False
        | prevCls == LbCR || prevCls == LbLF || prevCls == LbNL = True
        -- LB6
        | currentCls == LbBK || currentCls == LbCR
            || currentCls == LbLF || currentCls == LbNL = False
        -- LB7
        | currentCls == LbSP || currentCls == LbZW = False
        -- LB8
        | effPrevNoSp snapshot == Just LbZW = True
        -- LB8a
        | prevCls == LbZWJ = False
        -- LB9
        | isCmZwj currentCls
        , Just prev <- effPrev snapshot
        , not (blocksAbsorb prev) = False
        -- LB11
        | effective == LbWJ = False
        | effIn leftClass [LbWJ] = False
        -- LB12
        | effIn leftClass [LbGL] = False
        -- LB12a
        | effective == LbGL
        , glueKeepsLeft = False
        -- LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an
        -- is that opens a number and follows a space, as in "equals .35".
        | prevCls == LbSP
        , effective == LbIS
        , classAt 0 ahead == Just LbNU = True
        -- LB13
        | effective `elem` [LbCL, LbCP, LbEX, LbIS, LbSY] = False
        -- LB14
        | effPrevNoSp snapshot == Just LbOP = False
        -- LB15a
        | inPiQuoteWindow snapshot = False
        -- LB15b
        | isPfQuote currentCp effective
        , finalQuoteCloses ahead = False
        -- LB15d
        | effective == LbIS = False
        -- LB16
        | effective == LbNS
        , effPrevNoSp snapshot == Just LbCL
            || effPrevNoSp snapshot == Just LbCP = False
        -- LB17
        | effective == LbB2
        , effPrevNoSp snapshot == Just LbB2 = False
        -- LB18
        | prevCls == LbSP = True
        -- LB19 and LB19a. A quote neither breaks before nor after, except on
        -- the OUTER side of an initial or final punctuation quote standing in
        -- contiguous East Asian content — there the default break applies, so
        -- a line may break at the quote boundary. The inner side stays
        -- unbroken, being the boundary inside the quote's own scope.
        | effective == LbQU
        , not (openQuoteInEastAsian currentCp effective ahead) = False
        | effIn leftClass [LbQU]
        , not (closeQuoteInEastAsian currentCp) = False
        -- LB20
        | effective == LbCB = True
        | effIn leftClass [LbCB] = True
        -- LB20.1, UCD 17.0: an explicit hyphen joins a following letter only
        -- where its own left context is outside a word, the same context
        -- LB20a requires. A mid-word HH falls through to LB31.
        | effIn leftClass [LbHH]
        , effective == LbAL || effective == LbHL
        , hyphenLeftContextOpens = False
        -- LB20a, with UCD 17.0's right side broadened to HL beside AL.
        | effective == LbAL || effective == LbHL
        , hyphenCarriesLeft
        , hyphenLeftContextOpens = False
        -- LB21
        | effective `elem` [LbBA, LbHY, LbHH, LbNS] = False
        | effIn leftClass [LbBB] = False
        -- LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what
        -- comes next unless that is itself HL. A BA does not glue here.
        | effPrevPrev snapshot == Just LbHL
        , hyphenIsHyOr2010
        , effective /= LbHL = False
        -- LB21b
        | effective == LbHL
        , effIn leftClass [LbSY] = False
        -- LB22
        | effective == LbIN = False
        -- LB23
        | effective == LbNU, effIn leftClass [LbAL, LbHL] = False
        | effective == LbAL || effective == LbHL
        , effIn leftClass [LbNU] = False
        -- LB23a
        | effective `elem` [LbID, LbEB, LbEM]
        , effIn leftClass [LbPR] = False
        | effective == LbPO, effIn leftClass [LbID, LbEB, LbEM] = False
        -- LB24
        | effective == LbAL || effective == LbHL
        , effIn leftClass [LbPR, LbPO] = False
        | effective == LbPR || effective == LbPO
        , effIn leftClass [LbAL, LbHL] = False
        -- LB25, closing an open numeric chain with a CL or CP suffix and a
        -- following PO or PR.
        | inNuChain snapshot
        , effective `elem` [LbCL, LbCP, LbPO, LbPR] = False
        -- LB25, opening a chain
        | effective == LbNU
        , effIn leftClass [LbPR, LbPO, LbHY, LbOP, LbIS] = False
        -- LB25, chain body
        | effective == LbNU, effIn leftClass [LbNU] = False
        -- LB25, extending an open chain across a SY
        | effective == LbNU, effIn leftClass [LbSY], inNuChain snapshot = False
        -- LB25, bracketed prefix: a PR joins an OP only when the OP itself
        -- opens a number, and neither is East Asian Fullwidth, Wide or
        -- Halfwidth.
        | effective == LbOP
        , effIn leftClass [LbPR]
        , not (isEastAsianFullWide currentCp)
        , maybe False (not . isEastAsianFullWide) (effPrevCp snapshot)
        , classAt 0 ahead == Just LbNU = False
        -- LB26
        | effIn leftClass [LbJL]
        , effective `elem` [LbJL, LbJV, LbH2, LbH3] = False
        | effIn leftClass [LbJV, LbH2]
        , effective == LbJV || effective == LbJT = False
        | effIn leftClass [LbJT, LbH3], effective == LbJT = False
        -- LB27
        | effIn leftClass [LbJL, LbJV, LbJT, LbH2, LbH3]
        , effective == LbIN || effective == LbPO = False
        | effIn leftClass [LbPR]
        , effective `elem` [LbJL, LbJV, LbJT, LbH2, LbH3] = False
        -- LB28
        | effective == LbAL || effective == LbHL
        , effIn leftClass [LbAL, LbHL] = False
        -- LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class
        -- AL and stands in for a cluster base throughout.
        | effIn leftClass [LbAP]
        , effective == LbAK || effective == LbAS || currentCp == 0x25CC = False
        | leftIsAksaraBase
        , effective == LbVF || effective == LbVI = False
        | effPrev snapshot == Just LbVI
        , effPrevPrev snapshot `elem` [Just LbAK, Just LbAS]
            || effPrevPrevCp snapshot == Just 0x25CC
        , effective == LbAK || currentCp == 0x25CC = False
        | leftIsAksaraBase
        , effective == LbAK || effective == LbAS || currentCp == 0x25CC
        , nextSignificantIsVf ahead = False
        -- LB29
        | effective == LbAL || effective == LbHL
        , effIn leftClass [LbIS] = False
        -- LB30, where the bracket must not be East Asian Fullwidth, Wide or
        -- Halfwidth.
        | effective == LbOP
        , effIn leftClass [LbAL, LbHL, LbNU]
        , not (isEastAsianFullWide currentCp) = False
        | effective `elem` [LbAL, LbHL, LbNU]
        , effIn leftClass [LbCP]
        , not (isEastAsianFullWide prevCp) = False
        -- LB30a
        | effective == LbRI, odd (riRun snapshot) = False
        -- LB30b
        | effective == LbEM, effIn leftClass [LbEB] = False
        | effective == LbEM, previousIsUnassignedPictograph = False
        -- LB31
        | otherwise = True
      where
        -- LB9 and LB10 together: a CM or ZWJ takes the class of what it
        -- attaches to, or AL when nothing absorbs it.
        effective
            | not (isCmZwj currentCls) = currentCls
            | otherwise =
                case effPrev snapshot of
                    Nothing   -> LbAL
                    Just prev -> if blocksAbsorb prev then LbAL else currentCls

        leftClass
            | isCmZwj prevCls = effPrev snapshot
            | otherwise = Just prevCls

        glueKeepsLeft =
            case leftClass of
                Just cls ->
                    cls /= LbSP && cls /= LbBA && cls /= LbHY && cls /= LbHH
                Nothing -> True

        hyphenCarriesLeft =
            case (effPrev snapshot, effPrevCp snapshot) of
                (Just cls, Just cp) ->
                    cls == LbHY || cls == LbHH || isHyphenU2010 cp
                (Just cls, Nothing) -> cls == LbHY || cls == LbHH
                (Nothing, _cp) -> False

        hyphenIsHyOr2010 =
            case (effPrev snapshot, effPrevCp snapshot) of
                (Just cls, Just cp) -> cls == LbHY || isHyphenU2010 cp
                (Just cls, Nothing) -> cls == LbHY
                (Nothing, _cp) -> False

        hyphenLeftContextOpens =
            case effPrevPrev snapshot of
                Nothing -> True
                Just cls ->
                    cls == LbBK || cls == LbCR || cls == LbLF || cls == LbNL
                        || cls == LbSP || cls == LbZW || cls == LbCB
                        || cls == LbGL

        -- LB19a's outer-side exception on an initial-punctuation quote: the
        -- left context, the quote and the right context must all be East
        -- Asian.
        openQuoteInEastAsian cp cls ahead' =
            isPiQuote cp cls
                && isEastAsianOrAmbiguous prevCp
                && isEastAsianOrAmbiguous cp
                && maybe False isEastAsianOrAmbiguous (codepointAt 0 ahead')

        -- The same exception on a final-punctuation quote, read from the left:
        -- the character before the quote, the quote, and the current one.
        closeQuoteInEastAsian cp =
            case effPrevCp snapshot of
                Nothing -> False
                Just quoteCp ->
                    isPfQuote quoteCp LbQU
                        && maybe False isEastAsianOrAmbiguous
                            (effPrevPrevCp snapshot)
                        && isEastAsianOrAmbiguous quoteCp
                        && isEastAsianOrAmbiguous cp

        -- LB15b holds when the final quote is last, or when what follows it
        -- cannot itself open a line.
        finalQuoteCloses ahead' =
            case classAt 0 ahead' of
                Nothing -> True
                Just next ->
                    next `elem`
                        [ LbSP, LbGL, LbWJ, LbCL, LbQU, LbCP, LbEX, LbIS
                        , LbSY, LbBK, LbCR, LbLF, LbNL, LbZW
                        ]

        leftIsAksaraBase =
            effIn leftClass [LbAK, LbAS]
                || (effPrevCp snapshot == Just 0x25CC
                        && effPrev snapshot == Just LbAL)

        previousIsUnassignedPictograph =
            case effPrevCp snapshot of
                Nothing -> False
                Just cp ->
                    isExtPict cp && generalCategoryOf cp == GcCn

-- | The class at an offset into a suffix, or 'Nothing' past its end.
classAt :: Int -> [(Int, LineBreakClass)] -> Maybe LineBreakClass
classAt offset pairs = fmap snd (elementAt offset pairs)

-- | The codepoint at an offset into a suffix, or 'Nothing' past its end.
codepointAt :: Int -> [(Int, LineBreakClass)] -> Maybe Int
codepointAt offset pairs = fmap fst (elementAt offset pairs)

-- | The element at an offset, or 'Nothing' past the end. Total, so no rule
-- reads outside the sequence it was given.
elementAt :: Int -> [a] -> Maybe a
elementAt offset xs
    | offset < 0 = Nothing
    | otherwise =
        case drop offset xs of
            element : _rest -> Just element
            []              -> Nothing

-- | The fourth LB28a sub-rule looks past any @CM@ or @ZWJ@ the cluster
-- absorbs, so the character it tests is the first significant one ahead.
nextSignificantIsVf :: [(Int, LineBreakClass)] -> Bool
nextSignificantIsVf pairs =
    case dropWhile (isCmZwj . snd) pairs of
        (_cp, cls) : _rest -> cls == LbVF
        []                 -> False

-- ═════════════════════════════════════════════════════════════════════════════
--                                                            // entry // points
-- ═════════════════════════════════════════════════════════════════════════════

-- | One break-opportunity flag per boundary of the codepoint sequence, so a
-- sequence of @n@ codepoints yields @n + 1@ flags.
--
-- Entry @0@ is 'False' — LB2 forbids a break at the start of text — and entry
-- @n@ is 'True' per LB3, which requires one at the end.
lineBreaks :: [Int] -> [Bool]
lineBreaks codepoints =
    zipWith3 decideAt befores suffixes snapshots ++ [True]  -- LB3
  where
    pairs = [ (cp, resolvedClass cp) | cp <- codepoints ]

    -- One decision per codepoint position, each reading the character before
    -- it, the suffix from it onward, and the context accumulated before it.
    befores   = Nothing : map Just pairs
    suffixes  = take (length pairs) (iterate (drop 1) pairs)
    snapshots = take (length pairs) (scanl advance initialSnapshot pairs)

    decideAt before suffix snapshot =
        case before of
            Nothing     -> False                                     -- LB2
            Just prevPr -> breaksBefore prevPr suffix snapshot

-- | The codepoint sequence split at every break opportunity — the runs a
-- renderer may place on separate lines.
lineRuns :: [Int] -> [[Int]]
lineRuns codepoints = go (zip codepoints (drop 1 (lineBreaks codepoints))) []
  where
    go [] acc = if null acc then [] else [reverse acc]
    go ((cp, isBreak) : rest) acc
        | isBreak   = reverse (cp : acc) : go rest []
        | otherwise = go rest (cp : acc)
