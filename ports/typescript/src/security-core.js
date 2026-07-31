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
