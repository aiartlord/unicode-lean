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
  BidiControlBalance: "bidi-control-balance",
  NoncharacterControl: "noncharacter-control",
  HomoglyphConfusable: "homoglyph-confusable",
  MixedScriptAdmissibility: "mixed-script-admissibility",
});

let confusablesMapCache;
let attackTargetsCache;
let dataReader = null;

export function configureSecurityDataReader(reader) {
  if (typeof reader !== "function") {
    throw new TypeError("security data reader must be a function");
  }
  dataReader = reader;
  confusablesMapCache = undefined;
  attackTargetsCache = undefined;
}

export function configureSecurityData(data) {
  const confusables = String(data?.confusables ?? "");
  const knownAttackTargets = String(data?.knownAttackTargets ?? "");
  configureSecurityDataReader((name) => {
    if (name === "confusables.txt") {
      return confusables;
    }
    if (name === "KnownAttackTargets.txt") {
      return knownAttackTargets;
    }
    throw new Error(`unknown security data file: ${name}`);
  });
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
    family === Family.BidiControlBalance ||
    family === Family.NoncharacterControl ||
    family === Family.HomoglyphConfusable ||
    family === Family.MixedScriptAdmissibility
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
  return family === Family.HomoglyphConfusable || family === Family.MixedScriptAdmissibility ? "I" : "C";
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
  return makeFinding(Family.MixedScriptAdmissibility, "CrossScriptMix", fullSpanPositions(input));
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
  const step1 = caseFoldCodepoints(input);
  const step2 = substituteConfusables(step1);
  return caseFoldCodepoints(step2);
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
  const out = [];
  for (const cp of input) {
    out.push(...caseFoldCodepoint(cp));
  }
  return out;
}

function caseFoldCodepoint(cp) {
  try {
    return codepointsFromString(String.fromCodePoint(cp).toLowerCase());
  } catch {
    return [cp];
  }
}

function confusablesMap() {
  if (confusablesMapCache === undefined) {
    confusablesMapCache = parseConfusables(readDataFile("confusables.txt"));
  }
  return confusablesMapCache;
}

function knownAttackTargets() {
  if (attackTargetsCache === undefined) {
    attackTargetsCache = parseKnownAttackTargets(readDataFile("KnownAttackTargets.txt"));
  }
  return attackTargetsCache;
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

function parseKnownAttackTargets(raw) {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
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
