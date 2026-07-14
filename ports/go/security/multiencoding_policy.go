package security

type byteOrder int

const (
	bigEndian byteOrder = iota
	littleEndian
)

type decodeFailure struct {
	subThreat string
	offset    int
}

func malformedDecodeVerdict(profile Profile, mode Mode, family Family, subThreat string, offset int) Verdict {
	findings := []Finding{
		{
			Code:      reasonCode(family, subThreat),
			Family:    family,
			Severity:  2,
			Positions: []int{offset},
			SubThreat: subThreat,
			Detail:    string(family),
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

// ScanUTF16BE strictly decodes raw UTF-16BE bytes before applying codepoint policy.
func ScanUTF16BE(profile Profile, mode Mode, input []byte) Verdict {
	return scanUTF16(profile, mode, input, bigEndian)
}

// ScanUTF16LE strictly decodes raw UTF-16LE bytes before applying codepoint policy.
func ScanUTF16LE(profile Profile, mode Mode, input []byte) Verdict {
	return scanUTF16(profile, mode, input, littleEndian)
}

// ScanUTF32BE strictly decodes raw UTF-32BE bytes before applying codepoint policy.
func ScanUTF32BE(profile Profile, mode Mode, input []byte) Verdict {
	return scanUTF32(profile, mode, input, bigEndian)
}

// ScanUTF32LE strictly decodes raw UTF-32LE bytes before applying codepoint policy.
func ScanUTF32LE(profile Profile, mode Mode, input []byte) Verdict {
	return scanUTF32(profile, mode, input, littleEndian)
}

func scanUTF16(profile Profile, mode Mode, input []byte, order byteOrder) Verdict {
	decoded, failure := decodeUTF16ToCodepoints(input, order)
	if failure != nil {
		return malformedDecodeVerdict(
			profile,
			mode,
			FamilyMalformedUTF16,
			failure.subThreat,
			failure.offset,
		)
	}
	return Scan(profile, mode, decoded)
}

func scanUTF32(profile Profile, mode Mode, input []byte, order byteOrder) Verdict {
	decoded, failure := decodeUTF32ToCodepoints(input, order)
	if failure != nil {
		return malformedDecodeVerdict(
			profile,
			mode,
			FamilyMalformedUTF32,
			failure.subThreat,
			failure.offset,
		)
	}
	return Scan(profile, mode, decoded)
}

func decodeUTF16ToCodepoints(input []byte, order byteOrder) ([]uint32, *decodeFailure) {
	out := make([]uint32, 0, len(input)/2)
	offset := 0
	for offset < len(input) {
		if offset+2 > len(input) {
			return nil, &decodeFailure{subThreat: "TruncatedCodeUnit", offset: len(input)}
		}
		unit := uint32(readUint16(input, offset, order))
		unitOffset := offset
		offset += 2

		if unit >= 0xD800 && unit <= 0xDBFF {
			if offset+2 > len(input) {
				return nil, &decodeFailure{subThreat: "TruncatedSurrogatePair", offset: len(input)}
			}
			low := uint32(readUint16(input, offset, order))
			if low < 0xDC00 || low > 0xDFFF {
				return nil, &decodeFailure{subThreat: "InvalidSurrogatePair", offset: offset}
			}
			out = append(out, 0x10000+((unit-0xD800)<<10)+(low-0xDC00))
			offset += 2
		} else if unit >= 0xDC00 && unit <= 0xDFFF {
			return nil, &decodeFailure{subThreat: "LoneSurrogate", offset: unitOffset}
		} else {
			out = append(out, unit)
		}
	}
	return out, nil
}

func decodeUTF32ToCodepoints(input []byte, order byteOrder) ([]uint32, *decodeFailure) {
	if len(input)%4 != 0 {
		return nil, &decodeFailure{subThreat: "TruncatedCodeUnit", offset: len(input)}
	}

	out := make([]uint32, 0, len(input)/4)
	for offset := 0; offset < len(input); offset += 4 {
		cp := readUint32(input, offset, order)
		if cp >= 0xD800 && cp <= 0xDFFF {
			return nil, &decodeFailure{subThreat: "SurrogateCodepoint", offset: offset}
		}
		if cp > 0x10FFFF {
			return nil, &decodeFailure{subThreat: "CodepointBeyondMax", offset: offset}
		}
		out = append(out, cp)
	}
	return out, nil
}

func readUint16(input []byte, offset int, order byteOrder) uint16 {
	if order == bigEndian {
		return uint16(input[offset])<<8 | uint16(input[offset+1])
	}
	return uint16(input[offset]) | uint16(input[offset+1])<<8
}

func readUint32(input []byte, offset int, order byteOrder) uint32 {
	if order == bigEndian {
		return uint32(input[offset])<<24 |
			uint32(input[offset+1])<<16 |
			uint32(input[offset+2])<<8 |
			uint32(input[offset+3])
	}
	return uint32(input[offset]) |
		uint32(input[offset+1])<<8 |
		uint32(input[offset+2])<<16 |
		uint32(input[offset+3])<<24
}
