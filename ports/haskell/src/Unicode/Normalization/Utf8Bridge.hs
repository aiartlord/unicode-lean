{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                                    // unicode // normalization // utf8-bridge
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | UTF-8 byte bridge for the NFC codepoint pipeline. Codepoints are 'Int',
-- matching "Unicode.Codec.Utf8" and the @Unicode.Normalization@ algorithms.

module Unicode.Normalization.Utf8Bridge
    ( decodeToCodepoints
    , encodeCodepoint
    , encodeCodepoints
    , toNFCBytes
    , isNFCBytes
    ) where

import Data.ByteString (ByteString)

import qualified Unicode.Normalization.NFC as NFC
    ( toNFC
    )
import Unicode.Codec.Utf8
    ( encodeCodepoint
    , encodeCodepoints
    )
import qualified Unicode.Codec.Utf8 as Utf8
    ( decodeToCodepoints
    , isValidUtf8
    )

-- | Decode UTF-8 bytes to a codepoint list via the strict "Unicode.Codec.Utf8"
-- decoder.
decodeToCodepoints :: ByteString -> [Int]
decodeToCodepoints = Utf8.decodeToCodepoints

-- | NFC-normalise UTF-8 bytes, or 'Nothing' when the input is not valid
-- UTF-8. The output re-encodes the NFC codepoint sequence.
toNFCBytes :: ByteString -> Maybe ByteString
toNFCBytes bs =
    if Utf8.isValidUtf8 bs
        then Just (encodeCodepoints (NFC.toNFC (decodeToCodepoints bs)))
        else Nothing

-- | True iff @bs@ is already in NFC (valid UTF-8 that normalises to itself).
isNFCBytes :: ByteString -> Bool
isNFCBytes bs =
    case toNFCBytes bs of
        Just out -> out == bs
        Nothing  -> False
