export const Action = Object.freeze({
  Allow: "allow",
  Reject: "reject",
  Quarantine: "quarantine",
  Rewrite: "rewrite",
  Observe: "observe",
});

export const Mode = Object.freeze({
  Observe: "observe",
  Warn: "warn",
  Enforce: "enforce",
  Strict: "strict",
});

export const Profile = Object.freeze({
  GatewayHeader: "gateway-header",
  DomainName: "domain-name",
  DnsLabel: "dns-label",
  Url: "url",
  Username: "username",
  DisplayName: "display-name",
  ChatMessage: "chat-message",
  SourceCode: "source-code",
  OpaqueSecret: "opaque-secret",
  BinaryBlob: "binary-blob",
});

const PolicyLevel = Object.freeze({
  Restrictive: "restrictive",
  Moderate: "moderate",
  Minimal: "minimal",
});

export const Family = Object.freeze({
  MalformedUtf8: "malformed-utf8",
  MalformedUtf16: "malformed-utf16",
  MalformedUtf32: "malformed-utf32",
  TagBlockPayload: "tag-block-payload",
  VariationSelectorPayload: "variation-selector-payload",
  ZeroWidthPayload: "zero-width-payload",
  SurrogateReassembly: "surrogate-reassembly",
  BidiControlBalance: "bidi-control-balance",
  NoncharacterControl: "noncharacter-control",
  HomoglyphConfusable: "homoglyph-confusable",
  MixedScriptAdmissibility: "mixed-script-admissibility",
  RtlInjection: "rtl-injection",
  ConfusableBidiCompound: "confusable-bidi-compound",
  CovertDisplayCompound: "covert-display-compound",
});

let confusablesMapCache;
let caseFoldingMapCache;
let attackTargetsCache;
let legalVariationPairsCache;
let bidiTableCache;
let unicodeDataCache;
let compositionExclusionsCache;
let compositionTableCache;
let specialCasingCache;
let simpleLowerCache;
let simpleUpperCache;
let casedRangesCache;
let softDottedRangesCache;
let emojiRangesCache;
let dataReader = null;

export function configureSecurityDataReader(reader) {
  if (typeof reader !== "function") {
    throw new TypeError("security data reader must be a function");
  }
  dataReader = reader;
  confusablesMapCache = undefined;
  caseFoldingMapCache = undefined;
  attackTargetsCache = undefined;
  legalVariationPairsCache = undefined;
  bidiTableCache = undefined;
  unicodeDataCache = undefined;
  compositionExclusionsCache = undefined;
  compositionTableCache = undefined;
  specialCasingCache = undefined;
  simpleLowerCache = undefined;
  simpleUpperCache = undefined;
  casedRangesCache = undefined;
  softDottedRangesCache = undefined;
  emojiRangesCache = undefined;
  bip39WordlistCache = undefined;
}

export function configureSecurityData(data) {
  const confusables = requiredSecurityData(data, "confusables");
  const caseFolding = requiredSecurityData(data, "caseFolding");
  const knownAttackTargets = requiredSecurityData(data, "knownAttackTargets");
  const standardizedVariants = String(data?.standardizedVariants ?? "");
  const emojiVariationSequences = String(data?.emojiVariationSequences ?? "");
  const derivedBidiClass = requiredSecurityData(data, "derivedBidiClass");
  const unicodeData = requiredSecurityData(data, "unicodeData");
  const compositionExclusions = requiredSecurityData(data, "compositionExclusions");
  const derivedCoreProperties = requiredSecurityData(data, "derivedCoreProperties");
  const specialCasing = requiredSecurityData(data, "specialCasing");
  const emojiData = String(data?.emojiData ?? "");
  configureSecurityDataReader((name) => {
    if (name === "confusables.txt") {
      return confusables;
    }
    if (name === "CaseFolding.txt") {
      return caseFolding;
    }
    if (name === "KnownAttackTargets.txt") {
      return knownAttackTargets;
    }
    if (name === "StandardizedVariants.txt") {
      return standardizedVariants;
    }
    if (name === "emoji-variation-sequences.txt") {
      return emojiVariationSequences;
    }
    if (name === "DerivedBidiClass.txt") {
      return derivedBidiClass;
    }
    if (name === "UnicodeData.txt") {
      return unicodeData;
    }
    if (name === "CompositionExclusions.txt") {
      return compositionExclusions;
    }
    if (name === "DerivedCoreProperties.txt") {
      return derivedCoreProperties;
    }
    if (name === "SpecialCasing.txt") {
      return specialCasing;
    }
    if (name === "emoji-data.txt") {
      return emojiData;
    }
    throw new Error(`unknown security data file: ${name}`);
  });
}

function requiredSecurityData(data, name) {
  if (data == null || data[name] == null) {
    throw new TypeError(`missing required security data: ${name}`);
  }
  return String(data[name]);
}

export function scan(profile, mode, input) {
  const codepoints = Array.from(input, ensureCodepoint);
  const findings = detect(codepoints);
  return {
    action: decide(profile, mode, findings),
    profile,
    mode,
    input: codepoints,
    findings,
    normalized: null,
  };
}

export function scanUtf8(profile, mode, input) {
  const bytes = Array.from(input, ensureByte);
  const invalid = firstInvalidUtf8(bytes);
  if (invalid !== null) {
    return malformedDecodeVerdict(
      profile,
      mode,
      Family.MalformedUtf8,
      invalid.subThreat,
      invalid.offset,
    );
  }
  return scan(profile, mode, decodeUtf8ToCodepoints(bytes));
}

export function scanUtf16BE(profile, mode, input) {
  return scanUtf16(profile, mode, Array.from(input, ensureByte), "be");
}

export function scanUtf16LE(profile, mode, input) {
  return scanUtf16(profile, mode, Array.from(input, ensureByte), "le");
}

export function scanUtf32BE(profile, mode, input) {
  return scanUtf32(profile, mode, Array.from(input, ensureByte), "be");
}

export function scanUtf32LE(profile, mode, input) {
  return scanUtf32(profile, mode, Array.from(input, ensureByte), "le");
}

export const scanUTF8 = scanUtf8;
export const scanUTF16BE = scanUtf16BE;
export const scanUTF16LE = scanUtf16LE;
export const scanUTF32BE = scanUtf32BE;
export const scanUTF32LE = scanUtf32LE;

export function verdictToWire(verdict) {
  return {
    action: verdict.action,
    profile: verdict.profile,
    mode: verdict.mode,
    input: Array.from(verdict.input ?? []),
    findings: Array.from(verdict.findings ?? [], findingToWire),
    normalized: verdict.normalized ?? null,
  };
}

export function verdictJson(verdict) {
  return JSON.stringify(verdictToWire(verdict));
}

export const verdictJSON = verdictJson;

function detect(input) {
  const findings = [];

  const tagPositions = positionsWhere(input, isTagBlockAsciiPayload);
  if (tagPositions.length > 0) {
    findings.push(makeFinding(Family.TagBlockPayload, "DirectAscii", tagPositions));
  }

  const variation = variationSelectorFinding(input);
  if (variation !== null) {
    findings.push(variation);
  }

  const zeroWidthPositions = positionsWhere(input, isZeroWidthPayload);
  if (zeroWidthPositions.length > 0) {
    findings.push(makeFinding(Family.ZeroWidthPayload, "BareZeroWidth", zeroWidthPositions));
  }

  const surrogateReassembly = surrogateReassemblyFinding(input);
  if (surrogateReassembly !== null) {
    findings.push(surrogateReassembly);
  }

  const bidiPositions = positionsWhere(input, isBidiEmbeddingControl);
  if (bidiPositions.length > 0) {
    findings.push(makeFinding(Family.BidiControlBalance, "UnbalancedEmbedding", bidiPositions));
  }

  findings.push(...noncharacterControlFindings(input));

  const homoglyph = homoglyphConfusableFinding(input);
  if (homoglyph !== null) {
    findings.push(homoglyph);
  }
  const mixedScript = mixedScriptAdmissibilityFinding(input);
  if (mixedScript !== null) {
    findings.push(mixedScript);
  }
  const rtl = rtlInjectionFinding(input);
  if (rtl !== null) {
    findings.push(rtl);
  }
  const confusableBidi = confusableBidiCompoundFinding(input);
  if (confusableBidi !== null) {
    findings.push(confusableBidi);
  }
  const covertDisplay = covertDisplayCompoundFinding(input);
  if (covertDisplay !== null) {
    findings.push(covertDisplay);
  }

  return findings;
}

function decide(profile, mode, findings) {
  if (findings.length === 0) {
    return Action.Allow;
  }
  if (mode === Mode.Observe || mode === Mode.Warn) {
    return Action.Observe;
  }
  if (mode === Mode.Strict) {
    return Action.Reject;
  }

  const policy = policyOfProfile(profile);
  for (const finding of findings) {
    if (blocks(policy.level, finding.family)) {
      return policy.quarantine ? Action.Quarantine : Action.Reject;
    }
  }
  return Action.Allow;
}

function policyOfProfile(profile) {
  switch (profile) {
    case Profile.GatewayHeader:
    case Profile.DomainName:
    case Profile.DnsLabel:
    case Profile.SourceCode:
      return { level: PolicyLevel.Restrictive, quarantine: false };
    case Profile.Url:
      return { level: PolicyLevel.Moderate, quarantine: false };
    case Profile.Username:
      return { level: PolicyLevel.Moderate, quarantine: true };
    case Profile.DisplayName:
    case Profile.ChatMessage:
      return { level: PolicyLevel.Minimal, quarantine: true };
    case Profile.OpaqueSecret:
    case Profile.BinaryBlob:
      return { level: PolicyLevel.Minimal, quarantine: false };
    default:
      return { level: PolicyLevel.Restrictive, quarantine: false };
  }
}

function blocks(level, family) {
  if (level === PolicyLevel.Minimal) {
    return (
      family === Family.MalformedUtf8 ||
      family === Family.MalformedUtf16 ||
      family === Family.MalformedUtf32 ||
      family === Family.SurrogateReassembly ||
      family === Family.BidiControlBalance ||
      family === Family.NoncharacterControl
    );
  }
  return (
    family === Family.MalformedUtf8 ||
    family === Family.MalformedUtf16 ||
    family === Family.MalformedUtf32 ||
    family === Family.TagBlockPayload ||
    family === Family.VariationSelectorPayload ||
    family === Family.ZeroWidthPayload ||
    family === Family.SurrogateReassembly ||
    family === Family.BidiControlBalance ||
    family === Family.NoncharacterControl ||
    family === Family.HomoglyphConfusable ||
    family === Family.MixedScriptAdmissibility ||
    family === Family.ConfusableBidiCompound ||
    family === Family.CovertDisplayCompound
  );
}

function malformedDecodeVerdict(profile, mode, family, subThreat, offset) {
  const finding = makeFinding(family, subThreat, [offset]);
  const findings = [finding];
  return {
    action: decide(profile, mode, findings),
    profile,
    mode,
    input: [],
    findings,
    normalized: null,
  };
}

function makeFinding(family, subThreat, positions) {
  return {
    code: reasonCode(family, subThreat),
    family,
    severity: 2,
    positions: Array.from(positions),
    sub_threat: subThreat,
    detail: family,
  };
}

function findingToWire(finding) {
  return {
    code: finding.code,
    family: finding.family,
    severity: finding.severity,
    positions: Array.from(finding.positions ?? []),
    sub_threat: finding.sub_threat,
    detail: finding.detail,
  };
}

function reasonCode(family, subThreat) {
  return `unicode.security.${layer(family)}.${family}.${subThreat}`;
}

function layer(family) {
  if (family === Family.HomoglyphConfusable || family === Family.MixedScriptAdmissibility) {
    return "I";
  }
  if (family === Family.RtlInjection) {
    return "D";
  }
  if (family === Family.ConfusableBidiCompound || family === Family.CovertDisplayCompound) {
    return "X";
  }
  return "C";
}

function positionsWhere(input, pred) {
  const positions = [];
  for (let index = 0; index < input.length; index += 1) {
    if (pred(input[index])) {
      positions.push(index);
    }
  }
  return positions;
}

function isTagBlockAsciiPayload(cp) {
  return cp >= 0xe0020 && cp <= 0xe007e;
}

function variationSelectorFinding(input) {
  const positions = positionsWhere(input, isVariationSelector);
  if (positions.length === 0) {
    return null;
  }
  if (positions.length === 1 && isRegisteredVariationPosition(input, positions[0])) {
    return null;
  }

  let subThreat = "IllegalTarget";
  if (positions.length >= 4 && allSameAt(input, positions)) {
    subThreat = "RepeatedBase";
  } else if (decodeVariationSelectorRun(input, positions).length > 0) {
    subThreat = "DirectPayload";
  }
  return makeFinding(Family.VariationSelectorPayload, subThreat, positions);
}

function isVariationSelector(cp) {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef) || (cp >= 0x180b && cp <= 0x180d);
}

function isRegisteredVariationPosition(input, position) {
  return position > 0 && legalVariationPairs().has(variationPairKey(input[position - 1], input[position]));
}

function variationSelectorNibble(cp) {
  if (cp >= 0xfe00 && cp <= 0xfe0f) {
    return cp - 0xfe00;
  }
  if (cp >= 0xe0100 && cp <= 0xe01ef) {
    return cp - 0xe0100 + 16;
  }
  return null;
}

function decodeVariationSelectorRun(input, positions) {
  const out = [];
  let high = 0;
  let haveHigh = false;
  for (const position of positions) {
    const nibble = variationSelectorNibble(input[position]);
    if (nibble === null) {
      continue;
    }
    if (!haveHigh) {
      high = nibble;
      haveHigh = true;
    } else {
      out.push((high << 4) | nibble);
      haveHigh = false;
    }
  }
  return out;
}

function allSameAt(input, positions) {
  if (positions.length === 0) {
    return true;
  }
  const first = input[positions[0]];
  return positions.every((position) => input[position] === first);
}

function isZeroWidthPayload(cp) {
  return cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff;
}

function isBidiEmbeddingControl(cp) {
  return cp >= 0x202a && cp <= 0x202e;
}

// Surrogate-reassembly / malformed-byte-stream detection — a direct port of
// Unicode.Security.Covert.SurrogateReassembly. The family only applies to
// byte-stream-shaped input (every codepoint < 0x100, the looksLikeByteStream
// gate); it then runs the shared strict UTF-8 validator and projects the first
// violation onto a covert-layer sub-threat. The sub-threat tags differ from the
// malformed-utf8 reject-kind tags and are not reused.
function looksLikeByteStream(input) {
  return input.every((cp) => cp < 0x100);
}

function surrogateSubThreatOfRejectKind(kind) {
  switch (kind) {
    case "OverlongEncoding":
      return "Overlong";
    case "SurrogateCodepoint":
      return "Cesu8";
    case "TruncatedSequence":
      return "Truncated";
    case "InvalidStartByte":
      return "InvalidStartByte";
    case "InvalidContinuationByte":
      return "InvalidContinuation";
    case "CodepointBeyondMax":
      return "CodepointBeyondMax";
    default:
      throw new Error(`unknown UTF-8 reject kind: ${kind}`);
  }
}

// Module-faithful detect, mirroring
// Unicode.Security.Covert.SurrogateReassembly's `detect`. Any value > 0xFF
// is clamped to 0xFF (never a valid UTF-8 start byte), exactly as the Lean
// `toBytes` helper does, so out-of-range values surface as a malformed stream
// rather than being dropped. The byte-stream gate lives in the scan
// orchestrator (looksLikeByteStream), mirroring runAll.
function surrogateReassemblyDetect(input) {
  const clamped = input.map((cp) => (cp > 0xff ? 0xff : cp));
  const invalid = firstInvalidUtf8(clamped);
  if (invalid === null) {
    return null;
  }
  return {
    sub: surrogateSubThreatOfRejectKind(invalid.subThreat),
    positions: [invalid.offset],
  };
}

// Scan-orchestrator wrapper. Mirrors runAll: SurrogateReassembly only applies
// to byte-stream input (every codepoint <= 0xFF); on codepoint-array input the
// family is clear.
function surrogateReassemblyFinding(input) {
  if (!looksLikeByteStream(input)) {
    return null;
  }
  const detection = surrogateReassemblyDetect(input);
  if (detection === null) {
    return null;
  }
  return makeFinding(Family.SurrogateReassembly, detection.sub, detection.positions);
}

function noncharacterControlFindings(input) {
  const findings = [];
  const noncharacters = positionsWhere(input, isNoncharacter);
  if (noncharacters.length > 0) {
    findings.push(makeFinding(Family.NoncharacterControl, "Noncharacter", noncharacters));
  }
  const c0 = positionsWhere(input, isC0Control);
  if (c0.length > 0) {
    findings.push(makeFinding(Family.NoncharacterControl, "C0Control", c0));
  }
  const c1 = positionsWhere(input, isC1Control);
  if (c1.length > 0) {
    findings.push(makeFinding(Family.NoncharacterControl, "C1Control", c1));
  }
  return findings;
}

function homoglyphConfusableFinding(input) {
  let subThreat = "";
  if (homoglyphTargetMatch(input) !== null) {
    subThreat = "TargetMatch";
  } else if (input.some(isMathAlphanumeric)) {
    subThreat = "MathAlpha";
  } else if (input.some(isFullwidthHalfwidth)) {
    subThreat = "WidthClass";
  } else if (hasDecompositionSwap(input)) {
    subThreat = "DecompositionSwap";
  }

  if (subThreat === "") {
    return null;
  }
  return makeFinding(Family.HomoglyphConfusable, subThreat, fullSpanPositions(input));
}

function mixedScriptAdmissibilityFinding(input) {
  if (!hasCrossScriptMix(input)) {
    return null;
  }
  return makeFinding(Family.MixedScriptAdmissibility, mixedScriptSubThreat(input), fullSpanPositions(input));
}

// Right-to-left injection detection for LTR-declared fields — a direct
// port of Unicode.Security.Display.RtlInjection. The strong-RTL /
// strong-LTR predicates read Bidi_Class from the bundled
// DerivedBidiClass.txt, mirroring Unicode.Generated.DerivedBidiClass.lookup.

function isBidiFormatControl(cp) {
  return (
    (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)
  );
}

function isStrongRtl(cp) {
  const bidi = bidiStrong(cp);
  return bidi === "R" || bidi === "AL";
}

function isStrongLtr(cp) {
  return bidiStrong(cp) === "L";
}

function longestRtlRun(input) {
  let longest = 0;
  let longestStart = 0;
  let current = 0;
  let currentStart = 0;
  for (let index = 0; index < input.length; index += 1) {
    if (isStrongRtl(input[index])) {
      const newStart = current === 0 ? index : currentStart;
      current += 1;
      currentStart = newStart;
      if (current > longest) {
        longest = current;
        longestStart = newStart;
      }
    } else {
      current = 0;
    }
  }
  return [longest, longestStart];
}

function firstStrongChar(input) {
  for (let index = 0; index < input.length; index += 1) {
    if (isStrongRtl(input[index])) {
      return [index, true];
    }
    if (isStrongLtr(input[index])) {
      return [index, false];
    }
  }
  return null;
}

function rtlInjectionPhase3(input, strongRtl, runLen, runStart) {
  if (strongRtl === 0) {
    return null;
  }
  if (runLen >= 4) {
    return { sub: "MixedOverflow", positions: [runStart] };
  }
  for (let index = 0; index < input.length; index += 1) {
    if (isStrongRtl(input[index])) {
      return { sub: "StrongRTLInLTR", positions: [index] };
    }
  }
  // Unreachable when strongRtl > 0.
  return null;
}

function rtlInjectionFinding(input) {
  let strongRtl = 0;
  for (const cp of input) {
    if (isStrongRtl(cp)) {
      strongRtl += 1;
    }
  }
  const [runLen, runStart] = longestRtlRun(input);

  // Phase 1: bidi format-control trumps all.
  for (let index = 0; index < input.length; index += 1) {
    if (isBidiFormatControl(input[index])) {
      return makeFinding(Family.RtlInjection, "RloInLTRField", [index]);
    }
  }

  // Phase 2: leading-RTL field-direction takeover.
  const strong = firstStrongChar(input);
  let result;
  if (strong !== null && strong[1]) {
    result = { sub: "FieldTakeover", positions: [strong[0]] };
  } else {
    result = rtlInjectionPhase3(input, strongRtl, runLen, runStart);
  }
  if (result === null) {
    return null;
  }
  return makeFinding(Family.RtlInjection, result.sub, result.positions);
}

// Confusable-in-bidi-context compound detection (CVE-2021-42574 class) — a
// direct port of Unicode.Security.Boundary.ConfusableBidiCompound. A
// confusable (homoglyph) codepoint co-located with a bidi format-control is
// materially more dangerous than either alone: the homoglyph disguises an
// identifier while the bidi control reorders how a reviewer reads it. The
// finding fires only when both are present, reporting the offending positions
// as [confusablePos, bidiPos]. Override-class controls (LRE/RLE/LRO/RLO/PDF)
// take priority over isolate-class controls (LRI/RLI/FSI/PDI).

// True iff cp is a confusable source per UTS #39 §4 — i.e. it has a row in
// confusables.txt mapping it to a different skeleton sequence. Reuses the same
// confusables map the homoglyph detector reads.
function isConfusableSource(cp) {
  return confusablesMap().has(cp);
}

// True iff cp is an override-class bidi control (LRE, RLE, LRO, RLO, PDF).
function isOverride(cp) {
  return cp >= 0x202a && cp <= 0x202e;
}

// True iff cp is an isolate-class bidi control (LRI, RLI, FSI, PDI).
function isIsolate(cp) {
  return cp >= 0x2066 && cp <= 0x2069;
}

function firstPositionWhere(input, pred) {
  for (let index = 0; index < input.length; index += 1) {
    if (pred(input[index])) {
      return index;
    }
  }
  return null;
}

function confusableBidiCompoundFinding(input) {
  const confusablePos = firstPositionWhere(input, isConfusableSource);
  if (confusablePos === null) {
    return null;
  }
  const overridePos = firstPositionWhere(input, isOverride);
  if (overridePos !== null) {
    return makeFinding(Family.ConfusableBidiCompound, "ConfusableInOverride", [confusablePos, overridePos]);
  }
  const isolatePos = firstPositionWhere(input, isIsolate);
  if (isolatePos !== null) {
    return makeFinding(Family.ConfusableBidiCompound, "ConfusableInIsolate", [confusablePos, isolatePos]);
  }
  return null;
}

// Covert-display compound detection — a direct port of
// Unicode.Security.Boundary.CovertDisplayCompound. A bidi format-control
// that reorders the visible glyphs is materially more dangerous when the same
// input also carries a covert channel — an unregistered variation selector or a
// tag-block character — because the reorder hides where the covert payload
// sits. The finding fires only when a bidi control coincides with one of those
// covert classes, reporting [bidiPos, covertPos]. A suspicious variation
// selector (one that does not form a registered pair) takes priority over a
// tag-block character.

// True iff cp is in the tag-block range U+E0000..U+E007F.
function isTagBlockChar(cp) {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

// First position holding a suspicious variation selector — a VS that does not
// form a registered (base, VS) pair with its predecessor. Mirrors the
// .suspicious case of the Lean classifyPositions and reuses the same registered
// -pair check the variation-selector detector reads.
function firstSuspiciousVsPos(input) {
  for (let index = 0; index < input.length; index += 1) {
    if (isVariationSelector(input[index]) && !isRegisteredVariationPosition(input, index)) {
      return index;
    }
  }
  return null;
}

function covertDisplayCompoundFinding(input) {
  const bidiPos = firstPositionWhere(input, isBidiFormatControl);
  if (bidiPos === null) {
    return null;
  }
  const vsPos = firstSuspiciousVsPos(input);
  if (vsPos !== null) {
    return makeFinding(Family.CovertDisplayCompound, "BidiPlusUnregisteredVs", [bidiPos, vsPos]);
  }
  const tagPos = firstPositionWhere(input, isTagBlockChar);
  if (tagPos !== null) {
    return makeFinding(Family.CovertDisplayCompound, "BidiPlusTagBlock", [bidiPos, tagPos]);
  }
  return null;
}

function homoglyphTargetMatch(input) {
  const inputLetters = letterSkeleton(input);
  for (const target of knownAttackTargets()) {
    const targetCps = codepointsFromString(target);
    const targetLetters = letterSkeleton(targetCps);
    if (!sameNumbers(targetCps, input) && sameNumbers(targetLetters, inputLetters)) {
      return target;
    }
  }
  return null;
}

function letterSkeleton(input) {
  return iteratedSkeleton(input).filter(
    (cp) => !isCombiningMark(cp) && !isDefaultIgnorableCodepoint(cp) && !isWhiteSpaceCodepoint(cp),
  );
}

function iteratedSkeleton(input) {
  let current = Array.from(input);
  for (let index = 0; index < 8; index += 1) {
    const next = skeleton(current);
    if (sameNumbers(next, current)) {
      return current;
    }
    current = next;
  }
  return current;
}

function skeleton(input) {
  const step1 = toNfdCodepoints(input);
  const step2 = caseFoldCodepoints(step1);
  const step3 = substituteConfusables(step2);
  const step4 = caseFoldCodepoints(step3);
  return toNfdCodepoints(step4);
}

function substituteConfusables(input) {
  const table = confusablesMap();
  const out = [];
  for (const cp of input) {
    const replacement = table.get(cp);
    if (replacement !== undefined) {
      out.push(...replacement);
    } else {
      out.push(cp);
    }
  }
  return out;
}

function caseFoldCodepoints(input) {
  const table = caseFoldingMap();
  const out = [];
  for (const cp of input) {
    const replacement = table.get(cp);
    if (replacement !== undefined) {
      out.push(...replacement);
    } else {
      out.push(cp);
    }
  }
  return out;
}

// ── Canonical / compatibility normalization from the pinned UCD tables ──────
// Mirrors Unicode.Normalization.{Decompose,Reorder,Compose,NFKD,NFKC} and the
// verified Rust reference port. NFD/NFKD/NFKC are computed from UnicodeData.txt
// (field-3 CCC, field-5 decompositions) and CompositionExclusions.txt, NOT
// String.prototype.normalize, whose Unicode version tracks the JS runtime (ICU)
// rather than the pinned UCD.

const HANGUL_S_BASE = 0xac00;
const HANGUL_L_BASE = 0x1100;
const HANGUL_V_BASE = 0x1161;
const HANGUL_T_BASE = 0x11a7;
const HANGUL_L_COUNT = 19;
const HANGUL_V_COUNT = 21;
const HANGUL_T_COUNT = 28;
const HANGUL_N_COUNT = HANGUL_V_COUNT * HANGUL_T_COUNT;
const HANGUL_S_COUNT = HANGUL_L_COUNT * HANGUL_N_COUNT;

// Parse UnicodeData.txt into cp -> { ccc, canonical, compat }. The field-5
// decomposition carries a <tag> prefix for compatibility mappings; a mapping
// with no tag is canonical.
function parseUnicodeData(raw) {
  const out = new Map();
  for (const rawLine of raw.split("\n")) {
    if (rawLine === "") {
      continue;
    }
    const fields = rawLine.split(";");
    if (fields.length < 6) {
      continue;
    }
    const cp = parseHex(fields[0]);
    if (cp === null) {
      continue;
    }
    const ccc = parseInt(fields[3], 10);
    const decomp = fields[5].trim();
    let canonical = null;
    let compat = null;
    if (decomp !== "") {
      if (decomp.startsWith("<")) {
        compat = decomp
          .slice(decomp.indexOf(">") + 1)
          .trim()
          .split(/\s+/)
          .map((h) => parseInt(h, 16));
      } else {
        canonical = decomp.split(/\s+/).map((h) => parseInt(h, 16));
      }
    }
    out.set(cp, { ccc: Number.isNaN(ccc) ? 0 : ccc, canonical, compat });
  }
  return out;
}

function parseCompositionExclusions(raw) {
  const out = new Set();
  for (const rawLine of raw.split("\n")) {
    const body = rawLine.split("#", 1)[0].trim();
    if (body === "") {
      continue;
    }
    const cp = parseHex(body);
    if (cp !== null) {
      out.add(cp);
    }
  }
  return out;
}

function unicodeDataMap() {
  if (unicodeDataCache === undefined) {
    unicodeDataCache = parseUnicodeData(readDataFile("UnicodeData.txt"));
  }
  return unicodeDataCache;
}

function compositionExclusionsSet() {
  if (compositionExclusionsCache === undefined) {
    compositionExclusionsCache = parseCompositionExclusions(
      readDataFile("CompositionExclusions.txt"),
    );
  }
  return compositionExclusionsCache;
}

function canonicalCombiningClass(cp) {
  const entry = unicodeDataMap().get(cp);
  return entry === undefined ? 0 : entry.ccc;
}

// Composition table: inverse of the two-codepoint canonical decompositions,
// excluding singleton decompositions, Composition-Exclusion codepoints, and
// pairs whose first element is a non-starter (CCC != 0). Keyed "d,c".
function compositionTable() {
  if (compositionTableCache === undefined) {
    const table = new Map();
    const exclusions = compositionExclusionsSet();
    for (const [cp, entry] of unicodeDataMap()) {
      const decomp = entry.canonical;
      if (decomp === null || decomp.length !== 2) {
        continue;
      }
      if (exclusions.has(cp)) {
        continue;
      }
      if (canonicalCombiningClass(decomp[0]) !== 0) {
        continue;
      }
      table.set(`${decomp[0]},${decomp[1]}`, cp);
    }
    compositionTableCache = table;
  }
  return compositionTableCache;
}

function hangulDecompose(cp, out) {
  if (cp < HANGUL_S_BASE || cp >= HANGUL_S_BASE + HANGUL_S_COUNT) {
    return false;
  }
  const sIndex = cp - HANGUL_S_BASE;
  out.push(HANGUL_L_BASE + Math.floor(sIndex / HANGUL_N_COUNT));
  out.push(HANGUL_V_BASE + Math.floor((sIndex % HANGUL_N_COUNT) / HANGUL_T_COUNT));
  const tIndex = sIndex % HANGUL_T_COUNT;
  if (tIndex !== 0) {
    out.push(HANGUL_T_BASE + tIndex);
  }
  return true;
}

function hangulCompose(a, b) {
  if (
    a >= HANGUL_L_BASE &&
    a < HANGUL_L_BASE + HANGUL_L_COUNT &&
    b >= HANGUL_V_BASE &&
    b < HANGUL_V_BASE + HANGUL_V_COUNT
  ) {
    const lIndex = a - HANGUL_L_BASE;
    const vIndex = b - HANGUL_V_BASE;
    return HANGUL_S_BASE + (lIndex * HANGUL_V_COUNT + vIndex) * HANGUL_T_COUNT;
  }
  if (
    a >= HANGUL_S_BASE &&
    a < HANGUL_S_BASE + HANGUL_S_COUNT &&
    (a - HANGUL_S_BASE) % HANGUL_T_COUNT === 0 &&
    b > HANGUL_T_BASE &&
    b < HANGUL_T_BASE + HANGUL_T_COUNT
  ) {
    return a + (b - HANGUL_T_BASE);
  }
  return null;
}

function decomposeOne(cp, out) {
  if (hangulDecompose(cp, out)) {
    return;
  }
  const entry = unicodeDataMap().get(cp);
  if (entry !== undefined && entry.canonical !== null) {
    for (const child of entry.canonical) {
      decomposeOne(child, out);
    }
    return;
  }
  out.push(cp);
}

function compatDecomposeOne(cp, out) {
  if (hangulDecompose(cp, out)) {
    return;
  }
  const entry = unicodeDataMap().get(cp);
  if (entry !== undefined) {
    if (entry.compat !== null) {
      for (const child of entry.compat) {
        compatDecomposeOne(child, out);
      }
      return;
    }
    if (entry.canonical !== null) {
      for (const child of entry.canonical) {
        compatDecomposeOne(child, out);
      }
      return;
    }
  }
  out.push(cp);
}

// Stable canonical ordering: sort each non-starter run by CCC, preserving the
// relative order of equal-CCC codepoints (insertion sort that swaps only on a
// strict CCC decrease and never crosses a starter).
function canonicalOrder(values) {
  for (let index = 1; index < values.length; index += 1) {
    const currentCcc = canonicalCombiningClass(values[index]);
    if (currentCcc === 0) {
      continue;
    }
    for (let j = index; j > 0; j -= 1) {
      const previousCcc = canonicalCombiningClass(values[j - 1]);
      if (previousCcc === 0 || previousCcc <= currentCcc) {
        break;
      }
      const tmp = values[j - 1];
      values[j - 1] = values[j];
      values[j] = tmp;
    }
  }
}

// Canonical composition (UAX #15 D115), matching Unicode.Normalization.Compose
// and the D115-corrected blocked rule shared by the from-tables ports.
function canonicalCompose(seq) {
  if (seq.length === 0) {
    return [];
  }
  const table = compositionTable();
  const out = [];
  let starterIndex = -1;
  let lastCcc = -1;
  for (const cp of seq) {
    const cpCcc = canonicalCombiningClass(cp);
    if (starterIndex >= 0) {
      const starter = out[starterIndex];
      let composed = hangulCompose(starter, cp);
      if (composed === null) {
        const mapped = table.get(`${starter},${cp}`);
        composed = mapped === undefined ? null : mapped;
      }
      // Blocked check (UAX #15 D115): lastCcc !== 0 means a combiner is
      // buffered between the active starter and this candidate. A starter
      // candidate (cpCcc === 0) is blocked outright by any buffered combiner;
      // a non-starter is blocked when the buffered combiner has CCC >= its own.
      const blocked = lastCcc !== 0 && (cpCcc === 0 || lastCcc >= cpCcc);
      if (!blocked && composed !== null) {
        out[starterIndex] = composed;
        continue;
      }
    }
    out.push(cp);
    if (cpCcc === 0) {
      starterIndex = out.length - 1;
      lastCcc = 0;
    } else {
      lastCcc = cpCcc;
    }
  }
  return out;
}

function toNfdCodepoints(input) {
  const out = [];
  for (const cp of input) {
    decomposeOne(cp, out);
  }
  canonicalOrder(out);
  return out;
}

export function toNfkdCodepoints(input) {
  const out = [];
  for (const cp of input) {
    compatDecomposeOne(cp, out);
  }
  canonicalOrder(out);
  return out;
}

export function toNfcCodepoints(input) {
  return canonicalCompose(toNfdCodepoints(input));
}

export function toNfkcCodepoints(input) {
  return canonicalCompose(toNfkdCodepoints(input));
}

// ── UAX #21 case mapping (toLower / toUpper) from the pinned UCD tables ──────
// Mirrors Unicode.Casing: full case mappings from SpecialCasing.txt (one-to-many
// and context/locale rows) over the simple mappings in UnicodeData.txt fields
// 13/12, with the context predicates (Final_Sigma, After_Soft_Dotted,
// More_Above, Not_Before_Dot, After_I) driven by CCC and the Cased / Soft_Dotted
// properties from DerivedCoreProperties.txt. Independent of the runtime's
// String.prototype.toLowerCase, whose Unicode version tracks the JS engine.

const LOCALE_CONDITIONS = new Set(["tr", "az", "lt"]);

function parseSpecialCasing(raw) {
  const rows = new Map();
  for (const rawLine of raw.split("\n")) {
    const line = rawLine.split("#", 1)[0].trim();
    if (line === "") {
      continue;
    }
    const fields = line.split(";").map((f) => f.trim());
    if (fields.length < 4) {
      continue;
    }
    const hexList = (s) =>
      s === "" ? [] : s.split(/\s+/).map((h) => parseInt(h, 16));
    const code = parseInt(fields[0], 16);
    const row = {
      lower: hexList(fields[1]),
      title: hexList(fields[2]),
      upper: hexList(fields[3]),
      conditions: fields.length > 4 && fields[4] !== "" ? fields[4].split(/\s+/) : [],
    };
    if (!rows.has(code)) {
      rows.set(code, []);
    }
    rows.get(code).push(row);
  }
  return rows;
}

function specialCasingRows() {
  if (specialCasingCache === undefined) {
    specialCasingCache = parseSpecialCasing(readDataFile("SpecialCasing.txt"));
  }
  return specialCasingCache;
}

// Simple case mappings from UnicodeData.txt fields 13 (lowercase) / 12
// (uppercase); a codepoint absent from a map cases to itself.
function parseSimpleCaseMappings() {
  const lower = new Map();
  const upper = new Map();
  for (const line of readDataFile("UnicodeData.txt").split("\n")) {
    if (line === "") {
      continue;
    }
    const fields = line.split(";");
    if (fields.length < 15) {
      continue;
    }
    const cp = parseInt(fields[0], 16);
    if (fields[12] !== "") {
      upper.set(cp, parseInt(fields[12], 16));
    }
    if (fields[13] !== "") {
      lower.set(cp, parseInt(fields[13], 16));
    }
  }
  return { lower, upper };
}

function simpleLowercase(cp) {
  if (simpleLowerCache === undefined) {
    const maps = parseSimpleCaseMappings();
    simpleLowerCache = maps.lower;
    simpleUpperCache = maps.upper;
  }
  const mapped = simpleLowerCache.get(cp);
  return mapped === undefined ? cp : mapped;
}

function simpleUppercase(cp) {
  if (simpleUpperCache === undefined) {
    const maps = parseSimpleCaseMappings();
    simpleLowerCache = maps.lower;
    simpleUpperCache = maps.upper;
  }
  const mapped = simpleUpperCache.get(cp);
  return mapped === undefined ? cp : mapped;
}

function parseDerivedProperty(name) {
  const out = [];
  for (const rawLine of readDataFile("DerivedCoreProperties.txt").split("\n")) {
    const line = rawLine.split("#", 1)[0].trim();
    if (line === "") {
      continue;
    }
    const parts = line.split(";");
    if (parts.length < 2 || parts[1].trim() !== name) {
      continue;
    }
    const field = parts[0].trim();
    const dots = field.indexOf("..");
    if (dots < 0) {
      const cp = parseInt(field, 16);
      out.push([cp, cp]);
    } else {
      out.push([parseInt(field.slice(0, dots), 16), parseInt(field.slice(dots + 2), 16)]);
    }
  }
  return out;
}

function inRanges(ranges, cp) {
  return ranges.some(([lo, hi]) => lo <= cp && cp <= hi);
}

function isCased(cp) {
  if (casedRangesCache === undefined) {
    casedRangesCache = parseDerivedProperty("Cased");
  }
  return inRanges(casedRangesCache, cp);
}

function isSoftDotted(cp) {
  if (softDottedRangesCache === undefined) {
    softDottedRangesCache = parseDerivedProperty("Soft_Dotted");
  }
  return inRanges(softDottedRangesCache, cp);
}

// Context predicates (UAX #21). revPrefix is the preceding codepoints
// nearest-first; suffix the strictly-following ones.
function moreAboveAfter(suffix) {
  for (const cp of suffix) {
    const c = canonicalCombiningClass(cp);
    if (c === 230) return true;
    if (c === 0) return false;
  }
  return false;
}

function afterSoftDotted(revPrefix) {
  for (const cp of revPrefix) {
    if (isSoftDotted(cp)) return true;
    const c = canonicalCombiningClass(cp);
    if (c === 0 || c === 230) return false;
  }
  return false;
}

function afterI(revPrefix) {
  for (const cp of revPrefix) {
    if (cp === 0x0049) return true;
    const c = canonicalCombiningClass(cp);
    if (c === 0 || c === 230) return false;
  }
  return false;
}

function beforeDot(suffix) {
  for (const cp of suffix) {
    if (cp === 0x0307) return true;
    if (canonicalCombiningClass(cp) === 0) return false;
  }
  return false;
}

function hasCasedBefore(revPrefix) {
  for (const cp of revPrefix) {
    if (isCased(cp)) return true;
    if (canonicalCombiningClass(cp) === 0) return false;
  }
  return false;
}

function hasCasedAfter(suffix) {
  for (const cp of suffix) {
    if (isCased(cp)) return true;
    if (canonicalCombiningClass(cp) === 0) return false;
  }
  return false;
}

function finalSigma(revPrefix, suffix) {
  return hasCasedBefore(revPrefix) && !hasCasedAfter(suffix);
}

function localeMatches(locale, conditions) {
  if (!conditions.some((c) => LOCALE_CONDITIONS.has(c))) {
    return true;
  }
  return conditions.some(
    (c) =>
      (c === "tr" && locale === "turkish") ||
      (c === "az" && locale === "azeri") ||
      (c === "lt" && locale === "lithuanian"),
  );
}

function conditionsHold(locale, revPrefix, suffix, conditions) {
  if (!localeMatches(locale, conditions)) {
    return false;
  }
  for (const c of conditions) {
    if (LOCALE_CONDITIONS.has(c)) continue;
    let ok;
    if (c === "Final_Sigma") ok = finalSigma(revPrefix, suffix);
    else if (c === "Not_Final_Sigma") ok = !finalSigma(revPrefix, suffix);
    else if (c === "After_Soft_Dotted") ok = afterSoftDotted(revPrefix);
    else if (c === "More_Above") ok = moreAboveAfter(suffix);
    else if (c === "Not_Before_Dot") ok = !beforeDot(suffix);
    else if (c === "After_I") ok = afterI(revPrefix);
    else ok = false; // unrecognised context token
    if (!ok) return false;
  }
  return true;
}

function findSpecialRow(locale, revPrefix, suffix, cp) {
  const candidates = specialCasingRows().get(cp);
  if (candidates === undefined) {
    return null;
  }
  for (const row of candidates) {
    if (row.conditions.length > 0 && conditionsHold(locale, revPrefix, suffix, row.conditions)) {
      return row;
    }
  }
  for (const row of candidates) {
    if (row.conditions.length === 0) {
      return row;
    }
  }
  return null;
}

// Lowercase a codepoint sequence under `locale` (default when omitted).
export function toLowerCodepoints(input, locale = "default") {
  const out = [];
  const revPrefix = [];
  for (let index = 0; index < input.length; index += 1) {
    const cp = input[index];
    const suffix = input.slice(index + 1);
    const row = findSpecialRow(locale, revPrefix, suffix, cp);
    if (row !== null) {
      out.push(...row.lower);
    } else {
      out.push(simpleLowercase(cp));
    }
    revPrefix.unshift(cp);
  }
  return out;
}

// Uppercase a codepoint sequence under `locale` (default when omitted).
export function toUpperCodepoints(input, locale = "default") {
  const out = [];
  const revPrefix = [];
  for (let index = 0; index < input.length; index += 1) {
    const cp = input[index];
    const suffix = input.slice(index + 1);
    const row = findSpecialRow(locale, revPrefix, suffix, cp);
    if (row !== null) {
      out.push(...row.upper);
    } else {
      out.push(simpleUppercase(cp));
    }
    revPrefix.unshift(cp);
  }
  return out;
}

// ── locale-case-inversion: lowercase fold that inverts across locales ────────
// Mirrors Unicode.Security.Form.LocaleCaseInversion (Tier A2, the
// homograph-via-locale attack). Compares per-position lowerCodepoint across
// locales rather than diffing whole-string toLower, so the SpecialCasing context
// predicates evaluate with full context. Turkish divergence before Lithuanian.

function lowerCodepoint(locale, revPrefix, suffix, cp) {
  const row = findSpecialRow(locale, revPrefix, suffix, cp);
  return row !== null ? row.lower : [simpleLowercase(cp)];
}

function codepointsEqual(a, b) {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function firstLocaleDivergence(locale, input) {
  const revPrefix = [];
  for (let index = 0; index < input.length; index += 1) {
    const cp = input[index];
    const suffix = input.slice(index + 1);
    const defaultLower = lowerCodepoint("default", revPrefix, suffix, cp);
    const localeLower = lowerCodepoint(locale, revPrefix, suffix, cp);
    if (!codepointsEqual(defaultLower, localeLower)) {
      return index;
    }
    revPrefix.unshift(cp);
  }
  return null;
}

// Detect an input whose lowercase fold inverts across locales. Turkish
// divergence takes priority; Lithuanian is reached only when no Turkish
// divergence is found.
export function localeCaseInversionDetect(input) {
  const turkish = firstLocaleDivergence("turkish", input);
  if (turkish !== null) {
    return { sub: "TurkishCaseDivergence", positions: [turkish] };
  }
  const lithuanian = firstLocaleDivergence("lithuanian", input);
  if (lithuanian !== null) {
    return { sub: "LithuanianCaseDivergence", positions: [lithuanian] };
  }
  return { sub: null, positions: [] };
}

// ── normalization-bomb: NFD/NFKD expansion DoS detection ─────────────────────
// Mirrors Unicode.Security.Form.NormalizationBomb. Pure functional: compute NFD
// and NFKD lengths, then three priority-ordered checks — a per-codepoint blow-up
// scan, an overall NFKD ratio, an overall NFD ratio. Ratios are expressed in
// hundredths (integer percent) to avoid floats.

// Maximum allowed NFKD expansion per single codepoint. Hangul <= 3, Greek
// extended forms 4, the largest non-FDFA Arabic ligature (FDFB) 8; anything
// greater than 8 is flagged.
const MAX_NFKD_PER_CP = 8;

// Overall-sequence NFD expansion ratio threshold, in hundredths (300 = 3x).
// Pure Hangul sits at exactly 300 and stays clear under strict `>`.
const NFD_RATIO_PCT = 300;

// Overall-sequence NFKD expansion ratio threshold, in hundredths (400 = 4x).
const NFKD_RATIO_PCT = 400;

function firstBlowupCp(input) {
  for (let i = 0; i < input.length; i += 1) {
    if (toNfkdCodepoints([input[i]]).length > MAX_NFKD_PER_CP) {
      return i;
    }
  }
  return null;
}

function nfdRatioPct(input) {
  if (input.length === 0) {
    return 0;
  }
  return Math.floor((toNfdCodepoints(input).length * 100) / input.length);
}

function nfkdRatioPct(input) {
  if (input.length === 0) {
    return 0;
  }
  return Math.floor((toNfkdCodepoints(input).length * 100) / input.length);
}

export function normalizationBombDetect(input) {
  const blowup = firstBlowupCp(input);
  if (blowup !== null) {
    return { sub: "SingleCpBlowup", positions: [blowup] };
  }
  if (nfkdRatioPct(input) > NFKD_RATIO_PCT) {
    return { sub: "NfkdHighExpansion", positions: [] };
  }
  if (nfdRatioPct(input) > NFD_RATIO_PCT) {
    return { sub: "NfdHighExpansion", positions: [] };
  }
  return { sub: null, positions: [] };
}

// ── nfc-idempotence-witness: inputs not already in NFC (or, failing that, NFKC) ─
// Mirrors Unicode.Security.Form.NfcIdempotenceWitness. Compares the input
// element-wise against toNfc(input) and toNfkc(input), reporting the first
// divergent position: a mismatch against NFC is NonNfcForm; a sequence already
// in NFC but not NFKC is NonNfkcCompatForm. NFC divergence takes priority.

function firstDivergence(a, b) {
  const common = Math.min(a.length, b.length);
  for (let i = 0; i < common; i += 1) {
    if (a[i] !== b[i]) {
      return i;
    }
  }
  if (a.length !== b.length) {
    return common;
  }
  return null;
}

export function nfcIdempotenceWitnessDetect(input) {
  const nfc = toNfcCodepoints(input);
  const nfcPos = firstDivergence(input, nfc);
  if (nfcPos !== null) {
    return { sub: "NonNfcForm", positions: [nfcPos] };
  }
  const nfkc = toNfkcCodepoints(input);
  const nfkcPos = firstDivergence(input, nfkc);
  if (nfkcPos !== null) {
    return { sub: "NonNfkcCompatForm", positions: [nfkcPos] };
  }
  return { sub: null, positions: [] };
}

// ── bip39-canonical: BIP-39 mnemonic canonicalisation + wordlist checks ──────
// Mirrors Unicode.Security.Crypto.Bip39Canonical. Canonical form is
// NFKD -> toLower(default) -> collapse BIP-39 whitespace -> trim; detect runs
// six probes in priority order over the input and its canonical words.

// Declaration order matches Unicode.Generated.BIP39.allLanguages (English
// first, so a multi-wordlist-covered input resolves to English).
const BIP39_LANGUAGES = [
  "english",
  "japanese",
  "korean",
  "spanish",
  "chinese_simplified",
  "chinese_traditional",
  "french",
  "italian",
  "czech",
  "portuguese",
];

let bip39WordlistCache;

function bip39Wordlist(language) {
  if (bip39WordlistCache === undefined) {
    bip39WordlistCache = new Map();
  }
  let entries = bip39WordlistCache.get(language);
  if (entries === undefined) {
    const raw = readDataFile(`bip39/${language}.txt`);
    entries = new Set();
    for (const line of raw.split("\n")) {
      if (line !== "") {
        entries.add([...line].map((ch) => ch.codePointAt(0)).join(","));
      }
    }
    bip39WordlistCache.set(language, entries);
  }
  return entries;
}

function isInWordlist(language, word) {
  return bip39Wordlist(language).has(word.join(","));
}

function wordlistsContaining(word) {
  return BIP39_LANGUAGES.filter((language) => isInWordlist(language, word));
}

function uniqueLanguage(words) {
  for (const language of BIP39_LANGUAGES) {
    if (words.every((word) => isInWordlist(language, word))) {
      return language;
    }
  }
  return null;
}

function isBip39Whitespace(cp) {
  return cp === 0x0020 || cp === 0x3000;
}

function collapseWhitespaceToSingle(cps) {
  const out = [];
  let inWs = false;
  for (const cp of cps) {
    if (isBip39Whitespace(cp)) {
      if (!inWs) {
        out.push(0x0020);
      }
      inWs = true;
    } else {
      out.push(cp);
      inWs = false;
    }
  }
  return out;
}

function trimLeadingTrailing(cps) {
  let start = 0;
  let end = cps.length;
  while (start < end && cps[start] === 0x0020) start += 1;
  while (end > start && cps[end - 1] === 0x0020) end -= 1;
  return cps.slice(start, end);
}

export function bip39Canonical(cps) {
  return trimLeadingTrailing(
    collapseWhitespaceToSingle(toLowerCodepoints(toNfkdCodepoints(cps), "default")),
  );
}

function splitBip39Words(canonical) {
  const words = [];
  let current = [];
  for (const cp of canonical) {
    if (cp === 0x0020) {
      if (current.length > 0) {
        words.push(current);
        current = [];
      }
    } else {
      current.push(cp);
    }
  }
  if (current.length > 0) {
    words.push(current);
  }
  return words;
}

function countTrailingWhitespace(cps) {
  let count = 0;
  for (let i = cps.length - 1; i >= 0; i -= 1) {
    if (isBip39Whitespace(cps[i])) count += 1;
    else break;
  }
  return count;
}

function firstUppercasePos(cps) {
  for (let i = 0; i < cps.length; i += 1) {
    if (cps[i] >= 0x41 && cps[i] <= 0x5a) return i;
  }
  return null;
}

function firstWhitespaceRunPos(cps) {
  for (let i = 0; i < cps.length; i += 1) {
    if (isBip39Whitespace(cps[i])) {
      if (i === 0) return i;
      if (i + 1 < cps.length && isBip39Whitespace(cps[i + 1])) return i;
    }
  }
  return null;
}

function firstArrayDivergence(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return i;
  }
  if (a.length !== b.length) return n;
  return null;
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Detect a non-canonical or wordlist-mismatched BIP-39 mnemonic. Six probes in
// priority order (first hit wins), mirroring Bip39Canonical.detect.
export function bip39Detect(cps) {
  const canonical = bip39Canonical(cps);
  const words = splitBip39Words(canonical);

  const trailingCount = countTrailingWhitespace(cps);
  const uppercasePos = firstUppercasePos(cps);
  const whitespacePos = firstWhitespaceRunPos(cps);
  const nfkd = toNfkdCodepoints(cps);
  const nonNfkdPos = arraysEqual(cps, nfkd) ? null : firstArrayDivergence(cps, nfkd);

  const wordlistsPerWord = words.map(wordlistsContaining);
  const firstUnknownIdx = wordlistsPerWord.findIndex((langs) => langs.length === 0);

  let classify;
  if (trailingCount > 0) {
    classify = { isClear: false, language: null, sub: "TrailingWhitespace", positions: [cps.length - trailingCount] };
  } else if (uppercasePos !== null) {
    classify = { isClear: false, language: null, sub: "MixedCase", positions: [uppercasePos] };
  } else if (whitespacePos !== null) {
    classify = { isClear: false, language: null, sub: "WhitespaceAnomaly", positions: [whitespacePos] };
  } else if (nonNfkdPos !== null) {
    classify = { isClear: false, language: null, sub: "NonNFKD", positions: [nonNfkdPos] };
  } else if (firstUnknownIdx !== -1) {
    classify = { isClear: false, language: null, sub: "WordlistMismatch", positions: [firstUnknownIdx] };
  } else {
    const unique = uniqueLanguage(words);
    if (unique !== null) {
      classify = { isClear: true, language: unique, sub: null, positions: [] };
    } else {
      classify = { isClear: false, language: null, sub: "LanguageAmbiguous", positions: [] };
    }
  }
  return { input: cps, classify, canonicalForm: canonical, wordCount: words.length };
}

// ── hash-input-stability: canonical hash-input form drift detection ──────────
// Mirrors Unicode.Security.Crypto.HashInputStability (and the verified Rust
// port src/security/crypto/hash_input_stability.rs). Per UTS #39 §6.1 +
// RFC 4880/9580 + RFC 8785, an input hashed by a signer must be byte-identical
// to the input hashed by the verifier; if the two ends pick different canonical
// forms (NFC vs NFD, trim policy, line-ending convention) the resulting hashes
// diverge silently while both sides believe they signed the same content.
//
// The canonical (hash-stable) form is trimTrailing(toNfc(input)), where
// trimTrailing strips only ASCII whitespace {U+0020, U+0009, U+000A, U+000D};
// Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and is not
// stripped. NFC is the port's toNfcCodepoints, never a host normalizer.
//
// Six probes run in strict priority order (first hit wins):
//   1. encodingMismatch         (context: declaredEncoding)
//   2. webhookSignatureDrift     (context: serverBytes)
//   3. auditLogReinterpretation  (context: asWritten)
//   4. signedMessageRule         (context: rfcRule)
//   5. trailingWhitespace        (bare input)
//   6. normalizationDrift        (bare input)
//   7. clear
// Context-specific probes fire first because they carry more precise threat
// information than the generic probes.

// RFC canonicalisation profiles that the signedMessageRule probe checks
// against. Each value is the fixture-string tag of the rule (RfcRule::tag in
// the Rust port), so a rule and its tag are the same string.
export const RfcRule = Object.freeze({
  Pgp4880TrailingWhitespace: "pgp4880TrailingWhitespace",
  Pgp9580LineEnding: "pgp9580LineEnding",
  Rfc8785NfcRequirement: "rfc8785NfcRequirement",
  Rfc8259ControlChar: "rfc8259ControlChar",
  Rfc7515JwsBase64Url: "rfc7515JwsBase64Url",
  Rfc6376DkimRelaxed: "rfc6376DkimRelaxed",
  Rfc5751SmimeLineEnding: "rfc5751SmimeLineEnding",
});

const RFC_RULE_TAGS = Object.freeze(Object.values(RfcRule));

// Fixture-string identifier for an RfcRule. Identity here, since each RfcRule
// value already is its tag; kept for parity with the Rust RfcRule::tag API.
export function rfcRuleTag(rule) {
  return rule;
}

// Inverse of rfcRuleTag. Returns null for unrecognised strings.
export function rfcRuleFromTag(tag) {
  return RFC_RULE_TAGS.includes(tag) ? tag : null;
}

// Stable reason code for a hash-input-stability sub-threat (layer K).
export function hashInputStabilityReasonCode(subThreatTag) {
  return `unicode.security.K.hash-input-stability.${subThreatTag}`;
}

// True iff cp is an ASCII whitespace codepoint that line-oriented hash-input
// protocols treat as framing rather than content: SPACE, TAB, LF, CR.
function isHashAsciiWhitespace(cp) {
  return cp === 0x0020 || cp === 0x0009 || cp === 0x000a || cp === 0x000d;
}

// Count of trailing ASCII-whitespace codepoints in input.
function countTrailingAsciiWhitespace(input) {
  let count = 0;
  for (let i = input.length - 1; i >= 0; i -= 1) {
    if (isHashAsciiWhitespace(input[i])) count += 1;
    else break;
  }
  return count;
}

// Strip trailing ASCII whitespace.
function trimTrailingAsciiWhitespace(input) {
  return input.slice(0, input.length - countTrailingAsciiWhitespace(input));
}

// The hash-stable form of an input: NFC then trim, in spec order.
export function hashStable(input) {
  return trimTrailingAsciiWhitespace(toNfcCodepoints(input));
}

// Lower-case an ASCII letter (U+0041..U+005A -> U+0061..U+007A).
function hashAsciiLower(cp) {
  return cp >= 0x41 && cp <= 0x5a ? cp + 0x20 : cp;
}

// True iff label (after ASCII case-fold) names UTF-8: "utf-8", "UTF-8", "UTF8",
// "utf8". Non-ASCII characters pass through unchanged.
function isUtf8Label(label) {
  let normalised = "";
  for (const ch of label) {
    normalised += String.fromCodePoint(hashAsciiLower(ch.codePointAt(0)));
  }
  return normalised === "utf-8" || normalised === "utf8";
}

// True iff cp is a valid Unicode scalar value: in [0, 0x10FFFF] and not a
// surrogate [0xD800, 0xDFFF].
function isValidScalar(cp) {
  return cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff);
}

// First position in input holding a codepoint that is not a valid Unicode
// scalar, or null if every codepoint is valid.
function firstInvalidScalar(input) {
  for (let i = 0; i < input.length; i += 1) {
    if (!isValidScalar(input[i])) return i;
  }
  return null;
}

// Probe: encodingMismatch. Validity is dispatched first — an invalid scalar
// fires with detectedEnc = "invalid" regardless of the declared label;
// otherwise a non-UTF-8 label fires with detectedEnc = "utf-8" at position 0.
function encodingMismatchProbe(declared, input) {
  const invalid = firstInvalidScalar(input);
  if (invalid !== null) {
    return { declared, detected: "invalid", pos: invalid };
  }
  if (isUtf8Label(declared)) {
    return null;
  }
  return { declared, detected: "utf-8", pos: 0 };
}

// Probe: signedMessageRule for pgp4880TrailingWhitespace. Same condition as
// trailingWhitespace; returns the first position of the trailing run.
function pgp4880Violation(input) {
  const trailing = countTrailingAsciiWhitespace(input);
  return trailing > 0 ? input.length - trailing : null;
}

// Probe: signedMessageRule for pgp9580LineEnding. First bare LF (U+000A not
// preceded by CR) or bare CR (U+000D not followed by LF).
function pgp9580Violation(input) {
  for (let i = 0; i < input.length; i += 1) {
    const cp = input[i];
    if (cp === 0x000a) {
      const precededByCr = i > 0 && input[i - 1] === 0x000d;
      if (!precededByCr) return i;
    } else if (cp === 0x000d) {
      const followedByLf = i + 1 < input.length && input[i + 1] === 0x000a;
      if (!followedByLf) return i;
    }
  }
  return null;
}

// Probe: signedMessageRule for rfc8785NfcRequirement. Same condition as
// normalizationDrift; returns the first NFC divergence position.
function rfc8785Violation(input) {
  const nfc = toNfcCodepoints(input);
  return arraysEqual(input, nfc) ? null : firstArrayDivergence(input, nfc);
}

// Probe: signedMessageRule for rfc8259ControlChar. First C0 control
// (U+0000..U+001F).
function rfc8259Violation(input) {
  for (let i = 0; i < input.length; i += 1) {
    if (input[i] <= 0x1f) return i;
  }
  return null;
}

// True iff cp is in the JWS Base64URL alphabet [A-Za-z0-9_-].
function isBase64Url(cp) {
  return (
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    (cp >= 0x30 && cp <= 0x39) ||
    cp === 0x2d ||
    cp === 0x5f
  );
}

// Probe: signedMessageRule for rfc7515JwsBase64Url. First codepoint outside
// [A-Za-z0-9_-].
function rfc7515Violation(input) {
  for (let i = 0; i < input.length; i += 1) {
    if (!isBase64Url(input[i])) return i;
  }
  return null;
}

// True iff cp is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
function isDkimWhitespace(cp) {
  return cp === 0x20 || cp === 0x09;
}

// Probe: signedMessageRule for rfc6376DkimRelaxed. Position of the second
// whitespace codepoint in the first internal whitespace run longer than one.
function rfc6376Violation(input) {
  for (let i = 0; i < input.length; i += 1) {
    if (isDkimWhitespace(input[i]) && i > 0 && isDkimWhitespace(input[i - 1])) {
      return i;
    }
  }
  return null;
}

// Probe: signedMessageRule for rfc5751SmimeLineEnding. Reuses the PGP 9580
// bare-line-ending rule.
function rfc5751Violation(input) {
  return pgp9580Violation(input);
}

// Dispatch the RFC-rule probe. First violation position, or null if clean.
function rfcRuleViolation(rule, input) {
  switch (rule) {
    case RfcRule.Pgp4880TrailingWhitespace:
      return pgp4880Violation(input);
    case RfcRule.Pgp9580LineEnding:
      return pgp9580Violation(input);
    case RfcRule.Rfc8785NfcRequirement:
      return rfc8785Violation(input);
    case RfcRule.Rfc8259ControlChar:
      return rfc8259Violation(input);
    case RfcRule.Rfc7515JwsBase64Url:
      return rfc7515Violation(input);
    case RfcRule.Rfc6376DkimRelaxed:
      return rfc6376Violation(input);
    case RfcRule.Rfc5751SmimeLineEnding:
      return rfc5751Violation(input);
    default:
      return null;
  }
}

// The priority resolver: first hit wins, in the spec's fixed order. Each
// classify carries { isClear, tag, sub, positions }, where sub mirrors the
// Rust SubThreat variant fields.
function hashInputStabilityClassify(
  encodingHit,
  webhookHit,
  auditHit,
  rfcHit,
  trailingCount,
  inputLen,
  nonNfcPos,
) {
  if (encodingHit !== null) {
    return {
      isClear: false,
      tag: "EncodingMismatch",
      sub: {
        kind: "EncodingMismatch",
        declaredEnc: encodingHit.declared,
        detectedEnc: encodingHit.detected,
      },
      positions: [encodingHit.pos],
    };
  }
  if (webhookHit !== null) {
    return {
      isClear: false,
      tag: "WebhookSignatureDrift",
      sub: { kind: "WebhookSignatureDrift", firstPos: webhookHit },
      positions: [webhookHit],
    };
  }
  if (auditHit !== null) {
    return {
      isClear: false,
      tag: "AuditLogReinterpretation",
      sub: { kind: "AuditLogReinterpretation", firstDivergentPos: auditHit },
      positions: [auditHit],
    };
  }
  if (rfcHit !== null) {
    return {
      isClear: false,
      tag: "SignedMessageRule",
      sub: { kind: "SignedMessageRule", rfcRule: rfcHit.rule, firstPos: rfcHit.pos },
      positions: [rfcHit.pos],
    };
  }
  if (trailingCount > 0) {
    const p = inputLen - trailingCount;
    return {
      isClear: false,
      tag: "TrailingWhitespace",
      sub: { kind: "TrailingWhitespace", count: trailingCount },
      positions: [p],
    };
  }
  if (nonNfcPos !== null) {
    return {
      isClear: false,
      tag: "NormalizationDrift",
      sub: { kind: "NormalizationDrift", firstDivergentPos: nonNfcPos },
      positions: [nonNfcPos],
    };
  }
  return { isClear: true, tag: null, sub: null, positions: [] };
}

// The full hash-input-stability detection. Runs all six probes in priority
// order, context-bearing probes ahead of the generic ones. ctx fields
// (declaredEncoding, rfcRule, asWritten, serverBytes) are optional; the empty
// context leaves the four context-bearing probes silent.
export function hashInputStabilityDetectWithContext(ctx, input) {
  const context = ctx ?? {};
  const stable = hashStable(input);

  // Probe 1: encodingMismatch.
  const encodingHit =
    context.declaredEncoding != null
      ? encodingMismatchProbe(context.declaredEncoding, input)
      : null;

  // Probe 2: webhookSignatureDrift.
  const webhookHit =
    context.serverBytes != null ? firstArrayDivergence(input, context.serverBytes) : null;

  // Probe 3: auditLogReinterpretation.
  const auditHit =
    context.asWritten != null ? firstArrayDivergence(context.asWritten, input) : null;

  // Probe 4: signedMessageRule.
  let rfcHit = null;
  if (context.rfcRule != null) {
    const pos = rfcRuleViolation(context.rfcRule, input);
    if (pos !== null) rfcHit = { rule: context.rfcRule, pos };
  }

  // Probe 5: trailingWhitespace.
  const trailingCount = countTrailingAsciiWhitespace(input);

  // Probe 6: normalizationDrift.
  const nfc = toNfcCodepoints(input);
  const nonNfcPos = arraysEqual(input, nfc) ? null : firstArrayDivergence(input, nfc);

  const classify = hashInputStabilityClassify(
    encodingHit,
    webhookHit,
    auditHit,
    rfcHit,
    trailingCount,
    input.length,
    nonNfcPos,
  );

  return { input, classify, stableForm: stable, stableSize: stable.length };
}

// Convenience wrapper over hashInputStabilityDetectWithContext with the empty
// context — equivalent to running only the two bare-input probes
// (trailingWhitespace, normalizationDrift).
export function hashInputStabilityDetect(input) {
  return hashInputStabilityDetectWithContext({}, input);
}

// Mirrors Unicode.Security.Crypto.AiWatermarkDetectability (and the verified
// Rust port src/security/crypto/ai_watermark_detectability.rs). A character-
// level detector for inputs carrying codepoint patterns consistent with a known
// AI watermark scheme: does this input contain markers attributable to a
// watermarking protocol? Character-level detection alone cannot distinguish a
// legitimate provider watermark from injected markers impersonating one; the
// detector reports the matched scheme and leaves authentication downstream.
//
// Probe inventory (priority order, first match wins):
//   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
//   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
//   3. unknown                  — invisible markers from >= 2 distinct categories.
//   4. nnbspBoundary            — single-category NNBSP.
//   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
//   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
//   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
//   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
//   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
//  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
//
// The Emoji property table is bundled in the port's own data/emoji-data.txt
// (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
// adjacency probe parses the Emoji rows from it, never a host emoji library.
// Default_Ignorable membership reuses the port's own predicate, never a host
// normalizer.

// The conceptual watermark cue class a sub-threat probes for, drawn from the
// fixed vocabulary in Unicode.Generated.WatermarkSchemes.CueClass.
export const CueClass = Object.freeze({
  GreenListBias: "GreenListBias",
  PseudorandomSeq: "PseudorandomSeq",
  SemanticDrift: "SemanticDrift",
});

// Stable reason code for an ai-watermark-detectability sub-threat (layer K).
export function aiWatermarkDetectabilityReasonCode(subThreatTag) {
  return `unicode.security.K.ai-watermark-detectability.${subThreatTag}`;
}

// Human-facing classification tag for a sub-threat (its variant name / kind).
export function aiWatermarkSubThreatTag(sub) {
  return sub.kind;
}

// Map a sub-threat to the conceptual watermark cue class it probes for. Marker-
// encoded sub-threats route to PseudorandomSeq; vocabulary-bias to
// GreenListBias; stylistic-distribution to SemanticDrift; Unknown (multi-
// category mixing) implicates no single scheme.
export function aiWatermarkCueClass(sub) {
  switch (sub.kind) {
    case "NnbspBoundary":
    case "VariationSelectorCarrier":
    case "ZwjNonEmoji":
    case "DefaultIgnorableCarrier":
    case "Gpt5ZwspModulo":
    case "Adversarial":
      return CueClass.PseudorandomSeq;
    case "EmDashPattern":
    case "SmartQuoteAlternation":
      return CueClass.SemanticDrift;
    case "StatisticalTokenChoice":
      return CueClass.GreenListBias;
    case "Unknown":
    default:
      return null;
  }
}

// Parse the Emoji (Emoji=Yes) closed intervals from emoji-data.txt. Each non-
// comment row is `<range> ; <property> # <comment>`; keep only rows whose
// property is exactly Emoji.
function parseEmojiRanges(text) {
  const out = [];
  for (const rawLine of text.split("\n")) {
    const hashIdx = rawLine.indexOf("#");
    const body = hashIdx < 0 ? rawLine : rawLine.slice(0, hashIdx);
    const stripped = body.trim();
    if (stripped === "") {
      continue;
    }
    const fields = stripped.split(";");
    if (fields.length < 2) {
      continue;
    }
    if (fields[1].trim() !== "Emoji") {
      continue;
    }
    const range = fields[0].trim();
    const dots = range.indexOf("..");
    if (dots < 0) {
      const single = parseInt(range, 16);
      if (Number.isNaN(single)) {
        continue;
      }
      out.push([single, single]);
    } else {
      const lo = parseInt(range.slice(0, dots), 16);
      const hi = parseInt(range.slice(dots + 2), 16);
      if (Number.isNaN(lo) || Number.isNaN(hi)) {
        continue;
      }
      out.push([lo, hi]);
    }
  }
  return out;
}

function emojiRanges() {
  if (emojiRangesCache === undefined) {
    emojiRangesCache = parseEmojiRanges(readDataFile("emoji-data.txt"));
  }
  return emojiRangesCache;
}

// True iff cp has the Emoji = Yes property per emoji-data.txt.
function isEmojiCodepoint(cp) {
  for (const [lo, hi] of emojiRanges()) {
    if (lo <= cp && cp <= hi) {
      return true;
    }
  }
  return false;
}

// True iff cp is U+202F NARROW NO-BREAK SPACE.
function isNnbsp(cp) {
  return cp === 0x202f;
}

// True iff cp is U+200D ZERO WIDTH JOINER.
function isZwjCodepoint(cp) {
  return cp === 0x200d;
}

// True iff cp is a Variation Selector — the basic block U+FE00..U+FE0F
// (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256). This is
// the detector-specific predicate matching the Lean/Rust spec exactly, distinct
// from the port's broader isVariationSelector which also spans U+180B..U+180D.
function isAiWatermarkVariationSelector(cp) {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}

// True iff cp is U+200B ZERO WIDTH SPACE.
function isZwsp(cp) {
  return cp === 0x200b;
}

// True iff cp is U+2014 EM DASH.
function isEmDash(cp) {
  return cp === 0x2014;
}

// True iff cp is U+002D HYPHEN-MINUS (ASCII).
function isHyphenMinus(cp) {
  return cp === 0x002d;
}

// True iff cp is one of the four curly quotation marks: U+2018 / U+2019 (single
// open/close) and U+201C / U+201D (double open/close).
function isCurlyQuote(cp) {
  return cp === 0x2018 || cp === 0x2019 || cp === 0x201c || cp === 0x201d;
}

// True iff cp is an ASCII straight quote — U+0022 (double) or U+0027 (single).
function isStraightQuote(cp) {
  return cp === 0x0022 || cp === 0x0027;
}

// True iff input[i] is adjacent (immediate predecessor OR immediate successor)
// to an emoji codepoint. Two-sided check. Used by the VS and ZWJ probes to
// exclude legitimate emoji-context occurrences.
function isAdjacentToEmoji(input, i) {
  const prevIsEmoji = i > 0 && i - 1 < input.length && isEmojiCodepoint(input[i - 1]);
  const nextIsEmoji = i + 1 < input.length && isEmojiCodepoint(input[i + 1]);
  return prevIsEmoji || nextIsEmoji;
}

// All positions in input matching predicate p.
function allPositions(p, input) {
  const out = [];
  for (let i = 0; i < input.length; i += 1) {
    if (p(input[i])) {
      out.push(i);
    }
  }
  return out;
}

// True iff positions forms an arithmetic progression with all consecutive gaps
// within tolerance of the first gap. Empty + singleton lists are vacuously
// arithmetic. positions is assumed ascending, so gaps are non-negative.
function positionsAreArithmeticWithin(positions, tolerance) {
  if (positions.length < 2) {
    return true;
  }
  const firstGap = positions[1] - positions[0];
  for (let i = 0; i < positions.length - 1; i += 1) {
    const gap = positions[i + 1] - positions[i];
    if (!(gap <= firstGap + tolerance && firstGap <= gap + tolerance)) {
      return false;
    }
  }
  return true;
}

// First start-position at which pattern appears as a contiguous sub-slice of
// input, or null if absent.
function containsSublist(pattern, input) {
  if (pattern.length === 0 || pattern.length > input.length) {
    return null;
  }
  const maxStart = input.length - pattern.length;
  for (let start = 0; start <= maxStart; start += 1) {
    let matched = true;
    for (let j = 0; j < pattern.length; j += 1) {
      if (input[start + j] !== pattern[j]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      return start;
    }
  }
  return null;
}

// The AI-favored lexical-pattern catalog (each word as its codepoint sequence),
// transcribed verbatim from the pinned aiFavoredVocabulary literal in the Lean
// spec (parsed from Ucd/Security/AiFavoredVocabulary.txt and drift-gated there).
const AI_FAVORED_VOCABULARY = Object.freeze([
  [100, 101, 108, 118, 101],
  [100, 101, 108, 118, 105, 110, 103],
  [116, 97, 112, 101, 115, 116, 114, 121],
  [105, 110, 116, 114, 105, 99, 97, 116, 101],
  [110, 117, 97, 110, 99, 101, 100],
  [109, 111, 114, 101, 111, 118, 101, 114],
  [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
  [114, 101, 97, 108, 109],
  [101, 108, 117, 99, 105, 100, 97, 116, 101],
  [115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
  [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
  [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
  [112, 105, 118, 111, 116, 97, 108],
  [98, 111, 108, 115, 116, 101, 114],
  [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
  [116, 101, 115, 116, 97, 109, 101, 110, 116],
  [102, 111, 115, 116, 101, 114],
  [104, 111, 108, 105, 115, 116, 105, 99],
  [112, 97, 114, 97, 100, 105, 103, 109],
  [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
  [115, 112, 101, 97, 114, 104, 101, 97, 100],
  [109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
  [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
  [101, 109, 112, 111, 119, 101, 114],
  [101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
  [112, 114, 111, 102, 111, 117, 110, 100],
  [112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
  [99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
  [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
  [99, 114, 117, 99, 105, 97, 108],
  [100, 97, 117, 110, 116, 105, 110, 103],
  [114, 111, 98, 117, 115, 116],
  [115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
  [101, 110, 114, 105, 99, 104],
  [101, 120, 101, 109, 112, 108, 105, 102, 121],
  [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
  [100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
  [109, 101, 115, 109, 101, 114, 105, 122, 101],
  [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
  [105, 109, 98, 117, 101],
  [
    112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101,
  ],
  [
    112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101,
  ],
  [
    105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110,
    111, 116, 101,
  ],
  [105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103],
  [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
  [105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
  [100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
  [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
  [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
  [114, 101, 97, 108, 109, 32, 111, 102],
]);

// The detection function. Runs every probe in the fixed priority order (most-
// specific first); the first hit wins. See the module header for the probe
// inventory and the ordering rationale. ctx fields (zwspModuloTolerance,
// adversarialTolerance) default to 0 (exact arithmetic).
export function aiWatermarkDetectabilityDetectWithContext(ctx, input) {
  const context = ctx ?? {};
  const zwspModuloTolerance = context.zwspModuloTolerance ?? 0;
  const adversarialTolerance = context.adversarialTolerance ?? 0;

  const nnbspPositions = allPositions(isNnbsp, input);
  const nnbspCount = nnbspPositions.length;

  // Probe 1: adversarial — NNBSP too-regular.
  const adversarialFires =
    nnbspCount >= 3 && positionsAreArithmeticWithin(nnbspPositions, adversarialTolerance);

  // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
  const zwspPositions = allPositions(isZwsp, input);
  const zwspCount = zwspPositions.length;
  const zwspModuloFires =
    zwspCount >= 3 && positionsAreArithmeticWithin(zwspPositions, zwspModuloTolerance);

  const vsAllPos = allPositions(isAiWatermarkVariationSelector, input);
  const vsNonEmojiPos = vsAllPos.filter((i) => !isAdjacentToEmoji(input, i));
  const vsNonEmojiCount = vsNonEmojiPos.length;

  const zwjAllPos = allPositions(isZwjCodepoint, input);
  const zwjNonEmojiPos = zwjAllPos.filter((i) => !isAdjacentToEmoji(input, i));
  const zwjNonEmojiCount = zwjNonEmojiPos.length;

  // Probe 7: smartQuoteAlternation — curly quotes only.
  const curlyPositions = allPositions(isCurlyQuote, input);
  const curlyCount = curlyPositions.length;
  const hasStraightQuote = input.some((cp) => isStraightQuote(cp));
  const smartQuoteFires = curlyCount >= 2 && !hasStraightQuote;

  // Probe 8: emDashPattern — em-dashes without hyphen-minus.
  const emDashPositions = allPositions(isEmDash, input);
  const emDashCount = emDashPositions.length;
  const hasHyphenMinus = input.some((cp) => isHyphenMinus(cp));
  const emDashFires = emDashCount >= 2 && !hasHyphenMinus;

  // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
  // compared as a contiguous sub-slice of the input.
  let vocabHit = null;
  for (const pattern of AI_FAVORED_VOCABULARY) {
    const pos = containsSublist(pattern, input);
    if (pos !== null) {
      vocabHit = pos;
      break;
    }
  }

  // Residual default-ignorables (excluding VS and ZWJ, handled above).
  const isResidualDi = (cp) =>
    isDefaultIgnorableCodepoint(cp) && !isAiWatermarkVariationSelector(cp) && !isZwjCodepoint(cp);
  const diPositions = allPositions(isResidualDi, input);
  const diCount = diPositions.length;

  // Probe 3: unknown — invisible markers from >= 2 distinct categories.
  const categoryCount =
    (nnbspCount > 0 ? 1 : 0) +
    (vsNonEmojiCount > 0 ? 1 : 0) +
    (zwjNonEmojiCount > 0 ? 1 : 0) +
    (diCount > 0 ? 1 : 0);
  const unknownFires = categoryCount >= 2;
  const totalInvisibleCount = nnbspCount + vsNonEmojiCount + zwjNonEmojiCount + diCount;

  let sub;
  let positions;
  let firedCount;
  if (adversarialFires) {
    const firstPos = nnbspPositions.length > 0 ? nnbspPositions[0] : 0;
    sub = { kind: "Adversarial", impersonatedScheme: "nnbspBoundary", firstPos };
    positions = nnbspPositions;
    firedCount = nnbspCount;
  } else if (zwspModuloFires) {
    const firstPos = zwspPositions.length > 0 ? zwspPositions[0] : 0;
    sub = { kind: "Gpt5ZwspModulo", firstPos };
    positions = zwspPositions;
    firedCount = zwspCount;
  } else if (unknownFires) {
    const allInvisiblePos = [];
    for (let i = 0; i < input.length; i += 1) {
      const cp = input[i];
      if (
        isNnbsp(cp) ||
        isAiWatermarkVariationSelector(cp) ||
        isZwjCodepoint(cp) ||
        isDefaultIgnorableCodepoint(cp)
      ) {
        allInvisiblePos.push(i);
      }
    }
    sub = { kind: "Unknown", anomalyMarker: totalInvisibleCount };
    positions = allInvisiblePos;
    firedCount = totalInvisibleCount;
  } else if (nnbspCount > 0) {
    sub = { kind: "NnbspBoundary", markerCount: nnbspCount };
    positions = nnbspPositions;
    firedCount = nnbspCount;
  } else if (vsNonEmojiCount > 0) {
    sub = { kind: "VariationSelectorCarrier", markerCount: vsNonEmojiCount };
    positions = vsNonEmojiPos;
    firedCount = vsNonEmojiCount;
  } else if (zwjNonEmojiCount > 0) {
    sub = { kind: "ZwjNonEmoji", markerCount: zwjNonEmojiCount };
    positions = zwjNonEmojiPos;
    firedCount = zwjNonEmojiCount;
  } else if (smartQuoteFires) {
    const firstPos = curlyPositions.length > 0 ? curlyPositions[0] : 0;
    sub = { kind: "SmartQuoteAlternation", firstPos };
    positions = curlyPositions;
    firedCount = curlyCount;
  } else if (emDashFires) {
    const firstPos = emDashPositions.length > 0 ? emDashPositions[0] : 0;
    sub = { kind: "EmDashPattern", firstPos };
    positions = emDashPositions;
    firedCount = emDashCount;
  } else if (vocabHit !== null) {
    sub = { kind: "StatisticalTokenChoice", firstPos: vocabHit };
    positions = [vocabHit];
    firedCount = 1;
  } else if (diCount > 0) {
    sub = { kind: "DefaultIgnorableCarrier", markerCount: diCount };
    positions = diPositions;
    firedCount = diCount;
  } else {
    sub = null;
    positions = [];
    firedCount = 0;
  }

  const classify =
    sub === null
      ? { isClear: true, tag: null, sub: null, positions: [] }
      : { isClear: false, tag: sub.kind, sub, positions };

  return { input: Array.from(input), classify, markerCount: firedCount };
}

// Convenience wrapper over aiWatermarkDetectabilityDetectWithContext with the
// empty context — exact-arithmetic settings (zwspModuloTolerance = 0,
// adversarialTolerance = 0).
export function aiWatermarkDetectabilityDetect(input) {
  return aiWatermarkDetectabilityDetectWithContext({}, input);
}

function stringFromCodepoints(input) {
  let out = "";
  for (const cp of input) {
    out += String.fromCodePoint(cp);
  }
  return out;
}

function confusablesMap() {
  if (confusablesMapCache === undefined) {
    confusablesMapCache = parseConfusables(readDataFile("confusables.txt"));
  }
  return confusablesMapCache;
}

function caseFoldingMap() {
  if (caseFoldingMapCache === undefined) {
    caseFoldingMapCache = parseCaseFolding(readDataFile("CaseFolding.txt"));
  }
  return caseFoldingMapCache;
}

function bidiTable() {
  if (bidiTableCache === undefined) {
    bidiTableCache = parseDerivedBidi(readDataFile("DerivedBidiClass.txt"));
  }
  return bidiTableCache;
}

// Parse DerivedBidiClass.txt into two range lists, mirroring
// Unicode.Generated.DerivedBidiClass.lookup. Explicit ranges come from the
// DATA lines `LO..HI ; SHORT # ...` (or `CP ; SHORT # ...`), sorted by lower
// bound; default ranges come from the `# @missing: LO..HI; Long_Name` comment
// lines and are kept in file order (the last match wins). Only the strong
// distinction (R, AL, L) is retained — every other Bidi_Class collapses to
// "Other". SHORT tokens map R→R, AL→AL, L→L, else→Other; long @missing names
// map Right_To_Left→R, Arabic_Letter→AL, Left_To_Right→L, else→Other.
function parseDerivedBidi(raw) {
  const missingPrefix = "# @missing:";
  const explicit = [];
  const defaults = [];
  for (const line of raw.split("\n")) {
    if (line.startsWith(missingPrefix)) {
      const rest = line.slice(missingPrefix.length);
      const semi = rest.indexOf(";");
      if (semi === -1) {
        continue;
      }
      const range = parseBidiRange(rest.slice(0, semi));
      if (range === null) {
        continue;
      }
      defaults.push([range[0], range[1], strongOfLong(rest.slice(semi + 1).trim())]);
      continue;
    }
    const hash = line.indexOf("#");
    const body = (hash === -1 ? line : line.slice(0, hash)).trim();
    if (body === "") {
      continue;
    }
    const semi = body.indexOf(";");
    if (semi === -1) {
      continue;
    }
    const range = parseBidiRange(body.slice(0, semi));
    if (range === null) {
      continue;
    }
    explicit.push([range[0], range[1], strongOfShort(body.slice(semi + 1).trim())]);
  }
  explicit.sort((left, right) => left[0] - right[0]);
  return { explicit, defaults };
}

function parseBidiRange(field) {
  const text = field.trim();
  const dots = text.indexOf("..");
  if (dots !== -1) {
    const lo = parseHex(text.slice(0, dots));
    const hi = parseHex(text.slice(dots + 2));
    if (lo === null || hi === null) {
      return null;
    }
    return [lo, hi];
  }
  const cp = parseHex(text);
  if (cp === null) {
    return null;
  }
  return [cp, cp];
}

function strongOfShort(token) {
  if (token === "R") {
    return "R";
  }
  if (token === "AL") {
    return "AL";
  }
  if (token === "L") {
    return "L";
  }
  return "Other";
}

function strongOfLong(token) {
  if (token === "Right_To_Left") {
    return "R";
  }
  if (token === "Arabic_Letter") {
    return "AL";
  }
  if (token === "Left_To_Right") {
    return "L";
  }
  return "Other";
}

// Full Bidi_Class lookup (strong distinction only): binary-search the sorted
// explicit ranges first; on a miss, take the last matching @missing default
// range; otherwise fall back to "L".
function bidiStrong(cp) {
  const table = bidiTable();
  const explicit = table.explicit;
  let lo = 0;
  let hi = explicit.length;
  while (lo < hi) {
    const mid = lo + ((hi - lo) >> 1);
    const [rlo, rhi, cls] = explicit[mid];
    if (cp < rlo) {
      hi = mid;
    } else if (cp > rhi) {
      lo = mid + 1;
    } else {
      return cls;
    }
  }
  let result = "L";
  for (const [rlo, rhi, cls] of table.defaults) {
    if (rlo <= cp && cp <= rhi) {
      result = cls;
    }
  }
  return result;
}

function knownAttackTargets() {
  if (attackTargetsCache === undefined) {
    attackTargetsCache = parseKnownAttackTargets(readDataFile("KnownAttackTargets.txt"));
  }
  return attackTargetsCache;
}

function legalVariationPairs() {
  if (legalVariationPairsCache === undefined) {
    legalVariationPairsCache = new Set([
      ...parseLegalVariationPairs(readDataFile("StandardizedVariants.txt")),
      ...parseLegalVariationPairs(readDataFile("emoji-variation-sequences.txt")),
    ]);
  }
  return legalVariationPairsCache;
}

function parseConfusables(raw) {
  const out = new Map();
  for (const rawLine of raw.split("\n")) {
    const body = rawLine.split("#", 1)[0].trim();
    if (body === "") {
      continue;
    }
    const fields = body.split(";");
    if (fields.length < 2) {
      continue;
    }
    const src = parseHex(fields[0]);
    const target = parseCodepointField(fields[1]);
    if (src !== null && target.length > 0) {
      out.set(src, target);
    }
  }
  return out;
}

function parseCaseFolding(raw) {
  const out = new Map();
  for (const rawLine of raw.split("\n")) {
    const body = rawLine.split("#", 1)[0].trim();
    if (body === "") {
      continue;
    }
    const fields = body.split(";");
    if (fields.length < 3) {
      continue;
    }
    const status = fields[1].trim();
    if (status !== "C" && status !== "F") {
      continue;
    }
    const cp = parseHex(fields[0]);
    const mapping = parseCodepointField(fields[2]);
    if (cp !== null && mapping.length > 0) {
      out.set(cp, mapping);
    }
  }
  return out;
}

function parseKnownAttackTargets(raw) {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

function parseLegalVariationPairs(raw) {
  const out = [];
  for (const rawLine of raw.split("\n")) {
    const pairPart = rawLine.split("#", 1)[0].split(";", 1)[0].trim();
    if (pairPart === "") {
      continue;
    }
    const fields = pairPart.split(/\s+/u);
    if (fields.length !== 2) {
      continue;
    }
    const base = parseHex(fields[0]);
    const vs = parseHex(fields[1]);
    if (base !== null && vs !== null) {
      out.push(variationPairKey(base, vs));
    }
  }
  return out;
}

function variationPairKey(base, vs) {
  return `${base}:${vs}`;
}

function parseCodepointField(field) {
  return field
    .trim()
    .split(/\s+/u)
    .map(parseHex)
    .filter((cp) => cp !== null);
}

function parseHex(field) {
  const value = Number.parseInt(field.trim(), 16);
  return Number.isFinite(value) ? value : null;
}

function readDataFile(name) {
  if (dataReader === null) {
    throw new Error(
      "security data reader is not configured; import ./security.js for Node or call configureSecurityData/configureSecurityDataReader",
    );
  }
  return dataReader(name);
}

function fullSpanPositions(input) {
  return input.map((_, index) => index);
}

function isMathAlphanumeric(cp) {
  return cp >= 0x1d400 && cp <= 0x1d7ff;
}

function isFullwidthHalfwidth(cp) {
  return cp >= 0xff01 && cp <= 0xffef;
}

function isNoncharacter(cp) {
  if (cp >= 0xfdd0 && cp <= 0xfdef) {
    return true;
  }
  if (cp > 0x10ffff) {
    return false;
  }
  const low16 = cp & 0xffff;
  return low16 === 0xfffe || low16 === 0xffff;
}

function isC0Control(cp) {
  return (cp <= 0x1f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || cp === 0x7f;
}

function isC1Control(cp) {
  return cp >= 0x80 && cp <= 0x9f;
}

function isCombiningMark(cp) {
  return (
    (cp >= 0x0300 && cp <= 0x036f) ||
    (cp >= 0x1ab0 && cp <= 0x1aff) ||
    (cp >= 0x1dc0 && cp <= 0x1dff) ||
    (cp >= 0x20d0 && cp <= 0x20ff) ||
    (cp >= 0xfe20 && cp <= 0xfe2f)
  );
}

function hasDecompositionSwap(input) {
  for (let index = 1; index < input.length; index += 1) {
    const previous = input[index - 1];
    const current = input[index];
    if (isCombiningMark(current) && !isCombiningMark(previous)) {
      return true;
    }
    if (isCombiningMark(previous) && isCombiningMark(current) && previous > current) {
      return true;
    }
    if (composeHangulPair(previous, current)) {
      return true;
    }
  }
  return false;
}

function composeHangulPair(first, second) {
  const sBase = 0xac00;
  const lBase = 0x1100;
  const vBase = 0x1161;
  const tBase = 0x11a7;
  const lCount = 19;
  const vCount = 21;
  const tCount = 28;
  const nCount = vCount * tCount;
  const sCount = lCount * nCount;
  const isL = first >= lBase && first < lBase + lCount;
  const isV = second >= vBase && second < vBase + vCount;
  if (isL && isV) {
    return true;
  }
  const isLV = first >= sBase && first < sBase + sCount && (first - sBase) % tCount === 0;
  const isT = second > tBase && second < tBase + tCount;
  return isLV && isT;
}

function hasCrossScriptMix(input) {
  const seen = new Set();
  for (const cp of input) {
    const script = scriptClass(cp);
    if (script !== null) {
      seen.add(script);
    }
  }
  return seen.size >= 2;
}

// The specific script-collision sub-threat, matching the Lean source of truth:
// Latin/Cyrillic and Latin/Greek are named explicitly (Cyrillic before Greek);
// every other multi-script mix is ScriptMixOther.
function mixedScriptSubThreat(input) {
  const seen = new Set();
  for (const cp of input) {
    const script = scriptClass(cp);
    if (script !== null) {
      seen.add(script);
    }
  }
  if (seen.has("Latn") && seen.has("Cyrl")) {
    return "LatinCyrillic";
  }
  if (seen.has("Latn") && seen.has("Grek")) {
    return "LatinGreek";
  }
  return "ScriptMixOther";
}

function scriptClass(cp) {
  if ((cp >= 0x0041 && cp <= 0x005a) || (cp >= 0x0061 && cp <= 0x007a) || (cp >= 0x00c0 && cp <= 0x024f)) {
    return "Latn";
  }
  if ((cp >= 0x0370 && cp <= 0x03ff) || (cp >= 0x1f00 && cp <= 0x1fff)) {
    return "Grek";
  }
  if (cp >= 0x0400 && cp <= 0x052f) {
    return "Cyrl";
  }
  return null;
}

function isDefaultIgnorableCodepoint(cp) {
  return (
    cp === 0x00ad ||
    cp === 0x034f ||
    cp === 0x061c ||
    (cp >= 0x115f && cp <= 0x1160) ||
    (cp >= 0x17b4 && cp <= 0x17b5) ||
    (cp >= 0x180b && cp <= 0x180f) ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    cp === 0xfeff ||
    (cp >= 0xfff0 && cp <= 0xfff8) ||
    (cp >= 0xe0000 && cp <= 0xe0fff)
  );
}

function isWhiteSpaceCodepoint(cp) {
  return (
    cp === 0x0009 ||
    cp === 0x000a ||
    cp === 0x000b ||
    cp === 0x000c ||
    cp === 0x000d ||
    cp === 0x0020 ||
    cp === 0x0085 ||
    cp === 0x00a0 ||
    cp === 0x1680 ||
    (cp >= 0x2000 && cp <= 0x200a) ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    cp === 0x202f ||
    cp === 0x205f ||
    cp === 0x3000
  );
}

function scanUtf16(profile, mode, bytes, order) {
  const decoded = decodeUtf16ToCodepoints(bytes, order);
  if (decoded.failure !== null) {
    return malformedDecodeVerdict(profile, mode, Family.MalformedUtf16, decoded.failure.subThreat, decoded.failure.offset);
  }
  return scan(profile, mode, decoded.codepoints);
}

function decodeUtf16ToCodepoints(input, order) {
  const out = [];
  let offset = 0;
  while (offset < input.length) {
    if (offset + 2 > input.length) {
      return { codepoints: [], failure: { subThreat: "TruncatedCodeUnit", offset: input.length } };
    }
    const unitOffset = offset;
    const unit = readUint16(input, offset, order);
    offset += 2;

    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (offset + 2 > input.length) {
        return { codepoints: [], failure: { subThreat: "TruncatedSurrogatePair", offset: input.length } };
      }
      const low = readUint16(input, offset, order);
      if (low < 0xdc00 || low > 0xdfff) {
        return { codepoints: [], failure: { subThreat: "InvalidSurrogatePair", offset } };
      }
      out.push(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00));
      offset += 2;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return { codepoints: [], failure: { subThreat: "LoneSurrogate", offset: unitOffset } };
    } else {
      out.push(unit);
    }
  }
  return { codepoints: out, failure: null };
}

function scanUtf32(profile, mode, bytes, order) {
  const decoded = decodeUtf32ToCodepoints(bytes, order);
  if (decoded.failure !== null) {
    return malformedDecodeVerdict(profile, mode, Family.MalformedUtf32, decoded.failure.subThreat, decoded.failure.offset);
  }
  return scan(profile, mode, decoded.codepoints);
}

function decodeUtf32ToCodepoints(input, order) {
  if (input.length % 4 !== 0) {
    return { codepoints: [], failure: { subThreat: "TruncatedCodeUnit", offset: input.length } };
  }
  const out = [];
  for (let offset = 0; offset < input.length; offset += 4) {
    const cp = readUint32(input, offset, order);
    if (cp >= 0xd800 && cp <= 0xdfff) {
      return { codepoints: [], failure: { subThreat: "SurrogateCodepoint", offset } };
    }
    if (cp > 0x10ffff) {
      return { codepoints: [], failure: { subThreat: "CodepointBeyondMax", offset } };
    }
    out.push(cp);
  }
  return { codepoints: out, failure: null };
}

function readUint16(input, offset, order) {
  if (order === "be") {
    return (input[offset] << 8) | input[offset + 1];
  }
  return input[offset] | (input[offset + 1] << 8);
}

function readUint32(input, offset, order) {
  if (order === "be") {
    return (((input[offset] << 24) >>> 0) | (input[offset + 1] << 16) | (input[offset + 2] << 8) | input[offset + 3]) >>> 0;
  }
  return (input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16) | ((input[offset + 3] << 24) >>> 0)) >>> 0;
}

function firstInvalidUtf8(input) {
  let state = { inSequence: false, remaining: 0, accum: 0, minCp: 0 };
  let seqStart = 0;
  for (let index = 0; index < input.length; index += 1) {
    if (!state.inSequence) {
      seqStart = index;
    }
    const step = utf8DecodeStep(state, input[index]);
    if (step.rejected) {
      return { offset: step.kind === "OverlongEncoding" ? seqStart : index, subThreat: step.kind };
    }
    state = step.state;
  }
  if (state.inSequence) {
    return { offset: input.length, subThreat: "TruncatedSequence" };
  }
  return null;
}

function decodeUtf8ToCodepoints(input) {
  const out = [];
  let state = { inSequence: false, remaining: 0, accum: 0, minCp: 0 };
  for (const byte of input) {
    const step = utf8DecodeStep(state, byte);
    if (step.rejected) {
      return out;
    }
    if (!step.state.inSequence && (state.inSequence || byte < 0x80)) {
      out.push(step.emitted);
    }
    state = step.state;
  }
  return out;
}

function utf8DecodeStep(state, byte) {
  const n = byte;
  if (!state.inSequence) {
    if (n < 0x80) {
      return { state: { inSequence: false, remaining: 0, accum: 0, minCp: 0 }, emitted: n, kind: "", rejected: false };
    }
    if (n < 0xc2) {
      return { state, emitted: 0, kind: "InvalidStartByte", rejected: true };
    }
    if (n < 0xe0) {
      return { state: { inSequence: true, remaining: 1, accum: n & 0x1f, minCp: 0x80 }, emitted: 0, kind: "", rejected: false };
    }
    if (n < 0xf0) {
      return { state: { inSequence: true, remaining: 2, accum: n & 0x0f, minCp: 0x800 }, emitted: 0, kind: "", rejected: false };
    }
    if (n < 0xf5) {
      return { state: { inSequence: true, remaining: 3, accum: n & 0x07, minCp: 0x10000 }, emitted: 0, kind: "", rejected: false };
    }
    return { state, emitted: 0, kind: "InvalidStartByte", rejected: true };
  }

  if (n < 0x80 || n >= 0xc0) {
    return { state, emitted: 0, kind: "InvalidContinuationByte", rejected: true };
  }
  const next = (state.accum << 6) | (n & 0x3f);
  if (state.remaining === 1) {
    if (next < state.minCp) {
      return { state, emitted: 0, kind: "OverlongEncoding", rejected: true };
    }
    if (next >= 0xd800 && next <= 0xdfff) {
      return { state, emitted: 0, kind: "SurrogateCodepoint", rejected: true };
    }
    if (next > 0x10ffff) {
      return { state, emitted: 0, kind: "CodepointBeyondMax", rejected: true };
    }
    return { state: { inSequence: false, remaining: 0, accum: 0, minCp: 0 }, emitted: next, kind: "", rejected: false };
  }
  return {
    state: {
      inSequence: true,
      remaining: state.remaining - 1,
      accum: next,
      minCp: state.minCp,
    },
    emitted: 0,
    kind: "",
    rejected: false,
  };
}

function codepointsFromString(value) {
  return Array.from(value, (ch) => ch.codePointAt(0));
}

function sameNumbers(a, b) {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function ensureCodepoint(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0x10ffff) {
    throw new RangeError(`invalid codepoint: ${value}`);
  }
  return value;
}

function ensureByte(value) {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new RangeError(`invalid byte: ${value}`);
  }
  return value;
}

// Byte-layer refinement types.
//
// These layer over the same strict RFC 3629 UTF-8 validator the scanners use
// (firstInvalidUtf8, whose overlong / surrogate / out-of-range rejects are the
// blessed source of validity — never the host TextDecoder). No character-class
// or codepoint filtering happens here beyond structural UTF-8 validity; hardened
// identifier and printable profiles layer on top of these predicates.

// Guards the refinement-type constructors so the only entry points are the
// static smart constructors below, mirroring the private Rust constructors.
const REFINEMENT_BRAND = Symbol("unicode-security/byte-refinement");

// Structurally valid UTF-8 predicate, decoupled from any size bound. Exposed
// under the "blob" name so the framing — no character-class hardening — is
// explicit at the call site. Accepts a Uint8Array or a number[] of bytes.
export function isUtf8Blob(data) {
  const bytes = Array.from(data, ensureByte);
  return firstInvalidUtf8(bytes) === null;
}

// A byte sequence carrying its size bound and UTF-8 validity claim. Build one
// only via Utf8Blob.of; the direct constructor is guarded.
export class Utf8Blob {
  constructor(brand, value, maxBytes) {
    if (brand !== REFINEMENT_BRAND) {
      throw new TypeError("Utf8Blob is constructed via Utf8Blob.of");
    }
    this.value = value;
    this.maxBytes = maxBytes;
    Object.freeze(this);
  }

  // Build a Utf8Blob under the size bound maxBytes. Returns null when either the
  // bound or UTF-8 validity is violated.
  static of(data, maxBytes) {
    if (!Number.isInteger(maxBytes) || maxBytes < 0) {
      throw new RangeError(`invalid maxBytes bound: ${maxBytes}`);
    }
    const bytes = Object.freeze(Array.from(data, ensureByte));
    if (bytes.length > maxBytes) {
      return null;
    }
    if (firstInvalidUtf8(bytes) !== null) {
      return null;
    }
    return new Utf8Blob(REFINEMENT_BRAND, bytes, maxBytes);
  }

  // The underlying bytes.
  bytes() {
    return this.value;
  }
}

// A byte sequence validated as strict RFC 3629 UTF-8. The validity claim is
// pinned at the module boundary: validate is the only way to build one, so a
// downstream consumer that wants the raw bytes has to explicitly unwrap — which
// reads as "I am consuming the RFC 3629 claim here".
export class ValidatedUtf8 {
  constructor(brand, value) {
    if (brand !== REFINEMENT_BRAND) {
      throw new TypeError("ValidatedUtf8 is constructed via ValidatedUtf8.validate");
    }
    this.value = value;
    Object.freeze(this);
  }

  // Validate a byte sequence and, on success, return a ValidatedUtf8 carrying
  // the RFC 3629 validity claim. Returns null when the bytes fail the strict
  // state machine.
  static validate(data) {
    const bytes = Object.freeze(Array.from(data, ensureByte));
    if (firstInvalidUtf8(bytes) !== null) {
      return null;
    }
    return new ValidatedUtf8(REFINEMENT_BRAND, bytes);
  }

  // Borrow the validated bytes; the validity claim stays carried by this value.
  asBytes() {
    return this.value;
  }

  // Consume the validity claim, returning the underlying bytes. After this call
  // the caller owns the "these bytes are RFC 3629 valid" reasoning.
  unwrap() {
    return this.value;
  }
}
