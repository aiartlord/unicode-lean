-- Strict-UTF-8 reject taxonomy.
--
-- The six variants enumerate every category of byte sequence that a strict
-- RFC 3629 decoder rejects.  Each value is the stable fixture-row tag string
-- (identical to the Rust `Utf8RejectKind` variant name), so `utf8_reject_tag`
-- is the identity on these constants.

local Utf8RejectKind = {
  OverlongEncoding = "OverlongEncoding",
  SurrogateCodepoint = "SurrogateCodepoint",
  CodepointBeyondMax = "CodepointBeyondMax",
  TruncatedSequence = "TruncatedSequence",
  InvalidStartByte = "InvalidStartByte",
  InvalidContinuationByte = "InvalidContinuationByte",
}

return { Utf8RejectKind = Utf8RejectKind }
