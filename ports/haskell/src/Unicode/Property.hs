{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                                                        // unicode // property
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | @Unicode.Property@ — per-codepoint reads of the generated UCD property
-- tables.
--
-- The @Unicode.Generated.*@ modules state their property as a list of
-- inclusive ranges, which is the shape the UCD files have and the shape a
-- generator can emit without interpreting. Asking one of them about a single
-- codepoint means searching that list, and a scan pays the search once per
-- codepoint per property — @Line_Break@ alone is 3,654 ranges. Each lookup here
-- indexes its table once through 'RangeIndex' and answers in logarithmic time
-- from then on, so the index is built on first use and shared by every later
-- query.
--
-- Each answer carries the default its UCD file declares for a codepoint the
-- table does not list: @N@ for East_Asian_Width, @Cn@ for General_Category,
-- @XX@ for Line_Break. The tables assign one value per codepoint, so their
-- ranges are disjoint and the greatest-start lookup 'RangeIndex' performs
-- agrees with a first-match scan of the source list.
module Unicode.Property
    ( eastAsianWidthOf
    , isEastAsianFullWide
    , generalCategoryOf
    , lineBreakOf
    ) where

import Unicode.Generated.DerivedGeneralCategory
    ( GeneralCategory (GcCn)
    )
import qualified Unicode.Generated.DerivedGeneralCategory as CategoryTable
    ( explicitRanges
    )
import Unicode.Generated.EastAsianWidth
    ( EastAsianWidth (EawF, EawH, EawN, EawW)
    )
import qualified Unicode.Generated.EastAsianWidth as WidthTable
    ( explicitRanges
    )
import Unicode.Generated.LineBreakProperty
    ( LineBreakClass (LbXX)
    )
import qualified Unicode.Generated.LineBreakProperty as LineBreakTable
    ( explicitRanges
    )
import Unicode.RangeIndex (RangeMap)
import qualified Unicode.RangeIndex as RangeIndex
    ( classOf
    , rangeMapOf
    )

-- ═════════════════════════════════════════════════════════════════════════════
--                                                         // east-asian-width
-- ═════════════════════════════════════════════════════════════════════════════

-- | The UAX #11 @East_Asian_Width@ of a codepoint. @EastAsianWidth.txt@
-- declares @N@ over the whole codepoint space through its single @\@missing@
-- directive, so a codepoint the table does not list is @EawN@.
eastAsianWidthOf :: Int -> EastAsianWidth
eastAsianWidthOf codepoint =
    case RangeIndex.classOf codepoint widthIndex of
        Just width -> width
        Nothing    -> EawN

widthIndex :: RangeMap EastAsianWidth
widthIndex = RangeIndex.rangeMapOf WidthTable.explicitRanges

-- | True iff a codepoint is @East_Asian_Width@ @F@ (Fullwidth), @W@ (Wide) or
-- @H@ (Halfwidth) — the three classes UAX #14 LB25 and LB30 exclude from their
-- bracket and number rules.
isEastAsianFullWide :: Int -> Bool
isEastAsianFullWide codepoint =
    case eastAsianWidthOf codepoint of
        EawF -> True
        EawW -> True
        EawH -> True
        EawN -> False
        width -> width `seq` False

-- ═════════════════════════════════════════════════════════════════════════════
--                                                         // general-category
-- ═════════════════════════════════════════════════════════════════════════════

-- | The UAX #44 @General_Category@ of a codepoint. @UnicodeData.txt@ lists the
-- assigned codepoints, so one it does not list is unassigned: @GcCn@.
generalCategoryOf :: Int -> GeneralCategory
generalCategoryOf codepoint =
    case RangeIndex.classOf codepoint categoryIndex of
        Just category -> category
        Nothing       -> GcCn

categoryIndex :: RangeMap GeneralCategory
categoryIndex = RangeIndex.rangeMapOf CategoryTable.explicitRanges

-- ═════════════════════════════════════════════════════════════════════════════
--                                                               // line-break
-- ═════════════════════════════════════════════════════════════════════════════

-- | The UAX #14 @Line_Break@ class of a codepoint, as the UCD assigns it.
-- @LineBreak.txt@ declares @XX@ over the whole codepoint space through its
-- @\@missing@ directive, so a codepoint the table does not list is @LbXX@.
--
-- These are the raw values. LB1 tailors @AI@, @CJ@, @SA@, @SG@ and @XX@ into
-- the algorithm's working alphabet, reading 'generalCategoryOf' to decide
-- between @CM@ and @AL@ for @SA@.
lineBreakOf :: Int -> LineBreakClass
lineBreakOf codepoint =
    case RangeIndex.classOf codepoint lineBreakIndex of
        Just lineBreak -> lineBreak
        Nothing        -> LbXX

lineBreakIndex :: RangeMap LineBreakClass
lineBreakIndex = RangeIndex.rangeMapOf LineBreakTable.explicitRanges
