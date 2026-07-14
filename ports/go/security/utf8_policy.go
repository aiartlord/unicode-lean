package security

type utf8RejectKind string

const (
	utf8RejectOverlongEncoding        utf8RejectKind = "OverlongEncoding"
	utf8RejectSurrogateCodepoint      utf8RejectKind = "SurrogateCodepoint"
	utf8RejectCodepointBeyondMax      utf8RejectKind = "CodepointBeyondMax"
	utf8RejectTruncatedSequence       utf8RejectKind = "TruncatedSequence"
	utf8RejectInvalidStartByte        utf8RejectKind = "InvalidStartByte"
	utf8RejectInvalidContinuationByte utf8RejectKind = "InvalidContinuationByte"
)

type utf8State struct {
	inSequence bool
	remaining  int
	accum      uint32
	minCP      uint32
}

// ScanUTF8 strictly decodes raw UTF-8 bytes before applying codepoint policy.
func ScanUTF8(profile Profile, mode Mode, input []byte) Verdict {
	if offset, kind, invalid := firstInvalidUTF8Offset(input); invalid {
		subThreat := string(kind)
		findings := []Finding{
			{
				Code:      reasonCode(FamilyMalformedUTF8, subThreat),
				Family:    FamilyMalformedUTF8,
				Severity:  2,
				Positions: []int{offset},
				SubThreat: subThreat,
				Detail:    string(FamilyMalformedUTF8),
			},
		}
		return Verdict{
			Input:    []uint32{},
			Profile:  profile,
			Mode:     mode,
			Action:   decide(profile, mode, findings),
			Findings: findings,
		}
	}
	return Scan(profile, mode, decodeUTF8ToCodepoints(input))
}

func firstInvalidUTF8Offset(input []byte) (int, utf8RejectKind, bool) {
	state := utf8State{}
	seqStart := 0
	for index, b := range input {
		if !state.inSequence {
			seqStart = index
		}
		next, emitted, kind, rejected := utf8DecodeStep(state, b)
		if rejected {
			if kind == utf8RejectOverlongEncoding {
				return seqStart, kind, true
			}
			return index, kind, true
		}
		_ = emitted
		state = next
	}
	if state.inSequence {
		return len(input), utf8RejectTruncatedSequence, true
	}
	return 0, "", false
}

func utf8DecodeStep(state utf8State, b byte) (utf8State, uint32, utf8RejectKind, bool) {
	n := uint32(b)
	if !state.inSequence {
		switch {
		case n < 0x80:
			return utf8State{}, n, "", false
		case n < 0xC2:
			return state, 0, utf8RejectInvalidStartByte, true
		case n < 0xE0:
			return utf8State{inSequence: true, remaining: 1, accum: n & 0x1F, minCP: 0x80}, 0, "", false
		case n < 0xF0:
			return utf8State{inSequence: true, remaining: 2, accum: n & 0x0F, minCP: 0x800}, 0, "", false
		case n < 0xF5:
			return utf8State{inSequence: true, remaining: 3, accum: n & 0x07, minCP: 0x10000}, 0, "", false
		default:
			return state, 0, utf8RejectInvalidStartByte, true
		}
	}

	if n < 0x80 || n >= 0xC0 {
		return state, 0, utf8RejectInvalidContinuationByte, true
	}
	next := (state.accum << 6) | (n & 0x3F)
	if state.remaining == 1 {
		switch {
		case next < state.minCP:
			return state, 0, utf8RejectOverlongEncoding, true
		case next >= 0xD800 && next <= 0xDFFF:
			return state, 0, utf8RejectSurrogateCodepoint, true
		case next > 0x10FFFF:
			return state, 0, utf8RejectCodepointBeyondMax, true
		default:
			return utf8State{}, next, "", false
		}
	}
	return utf8State{
		inSequence: true,
		remaining:  state.remaining - 1,
		accum:      next,
		minCP:      state.minCP,
	}, 0, "", false
}

func decodeUTF8ToCodepoints(input []byte) []uint32 {
	out := make([]uint32, 0, len(input))
	state := utf8State{}
	for _, b := range input {
		next, emitted, _, rejected := utf8DecodeStep(state, b)
		if rejected {
			return out
		}
		if !next.inSequence && (state.inSequence || b < 0x80) {
			out = append(out, emitted)
		}
		state = next
	}
	return out
}
