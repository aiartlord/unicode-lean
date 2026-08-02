export type Action = "allow" | "reject" | "quarantine" | "rewrite" | "observe";
export type Mode = "observe" | "warn" | "enforce" | "strict";
export type Profile =
  | "gateway-header"
  | "domain-name"
  | "dns-label"
  | "url"
  | "username"
  | "display-name"
  | "chat-message"
  | "source-code"
  | "opaque-secret"
  | "binary-blob";

export interface Finding {
  code: string;
  family: string;
  severity: number;
  positions: number[];
  sub_threat: string;
  detail: string;
}

export interface Verdict {
  action: Action;
  profile: Profile | string;
  mode: Mode | string;
  input: number[];
  findings: Finding[];
  normalized: number[] | null;
}

export declare const Action: Readonly<Record<string, Action>>;
export declare const Mode: Readonly<Record<string, Mode>>;
export declare const Profile: Readonly<Record<string, Profile>>;
export declare const Family: Readonly<Record<string, string>>;

export declare function configureSecurityData(data: {
  confusables: string;
  caseFolding: string;
  knownAttackTargets: string;
  standardizedVariants?: string;
  emojiVariationSequences?: string;
  emojiData?: string;
  emojiZwjSequences?: string;
}): void;
export declare function configureSecurityDataReader(reader: (name: string) => string): void;
export declare function scan(profile: Profile | string, mode: Mode | string, input: Iterable<number>): Verdict;
export declare function scanUtf8(profile: Profile | string, mode: Mode | string, input: Iterable<number>): Verdict;
export declare function scanUtf16BE(profile: Profile | string, mode: Mode | string, input: Iterable<number>): Verdict;
export declare function scanUtf16LE(profile: Profile | string, mode: Mode | string, input: Iterable<number>): Verdict;
export declare function scanUtf32BE(profile: Profile | string, mode: Mode | string, input: Iterable<number>): Verdict;
export declare function scanUtf32LE(profile: Profile | string, mode: Mode | string, input: Iterable<number>): Verdict;
export declare const scanUTF8: typeof scanUtf8;
export declare const scanUTF16BE: typeof scanUtf16BE;
export declare const scanUTF16LE: typeof scanUtf16LE;
export declare const scanUTF32BE: typeof scanUtf32BE;
export declare const scanUTF32LE: typeof scanUtf32LE;
export declare function verdictToWire(verdict: Verdict): Verdict;
export declare function verdictJson(verdict: Verdict): string;
export declare const verdictJSON: typeof verdictJson;

export type ByteInput = Uint8Array | number[] | Iterable<number>;

export declare function isUtf8Blob(data: ByteInput): boolean;

export declare class Utf8Blob {
  private constructor();
  readonly value: number[];
  readonly maxBytes: number;
  static of(data: ByteInput, maxBytes: number): Utf8Blob | null;
  bytes(): number[];
}

export declare class ValidatedUtf8 {
  private constructor();
  readonly value: number[];
  static validate(data: ByteInput): ValidatedUtf8 | null;
  asBytes(): number[];
  unwrap(): number[];
}

// ── hash-input-stability (layer K) ─────────────────────────────────────────

export type RfcRule =
  | "pgp4880TrailingWhitespace"
  | "pgp9580LineEnding"
  | "rfc8785NfcRequirement"
  | "rfc8259ControlChar"
  | "rfc7515JwsBase64Url"
  | "rfc6376DkimRelaxed"
  | "rfc5751SmimeLineEnding";

export declare const RfcRule: Readonly<Record<string, RfcRule>>;
export declare function rfcRuleTag(rule: RfcRule): RfcRule;
export declare function rfcRuleFromTag(tag: string): RfcRule | null;
export declare function hashInputStabilityReasonCode(subThreatTag: string): string;

export type HashInputSubThreat =
  | { kind: "NormalizationDrift"; firstDivergentPos: number }
  | { kind: "TrailingWhitespace"; count: number }
  | { kind: "EncodingMismatch"; declaredEnc: string; detectedEnc: string }
  | { kind: "SignedMessageRule"; rfcRule: RfcRule; firstPos: number }
  | { kind: "AuditLogReinterpretation"; firstDivergentPos: number }
  | { kind: "WebhookSignatureDrift"; firstPos: number };

export interface HashInputClassification {
  isClear: boolean;
  tag: string | null;
  sub: HashInputSubThreat | null;
  positions: number[];
}

export interface HashInputContext {
  declaredEncoding?: string | null;
  rfcRule?: RfcRule | null;
  asWritten?: number[] | null;
  serverBytes?: number[] | null;
}

export interface HashInputVerdict {
  input: number[];
  classify: HashInputClassification;
  stableForm: number[];
  stableSize: number;
}

export declare function hashStable(input: number[]): number[];
export declare function hashInputStabilityDetect(input: number[]): HashInputVerdict;
export declare function hashInputStabilityDetectWithContext(
  ctx: HashInputContext,
  input: number[],
): HashInputVerdict;

// ── ai-watermark-detectability (layer K) ────────────────────────────────────

export type CueClass = "GreenListBias" | "PseudorandomSeq" | "SemanticDrift";

export declare const CueClass: Readonly<Record<string, CueClass>>;

export type AiWatermarkSubThreat =
  | { kind: "NnbspBoundary"; markerCount: number }
  | { kind: "VariationSelectorCarrier"; markerCount: number }
  | { kind: "ZwjNonEmoji"; markerCount: number }
  | { kind: "DefaultIgnorableCarrier"; markerCount: number }
  | { kind: "Gpt5ZwspModulo"; firstPos: number }
  | { kind: "EmDashPattern"; firstPos: number }
  | { kind: "SmartQuoteAlternation"; firstPos: number }
  | { kind: "StatisticalTokenChoice"; firstPos: number }
  | { kind: "Adversarial"; impersonatedScheme: string; firstPos: number }
  | { kind: "Unknown"; anomalyMarker: number };

export interface AiWatermarkClassification {
  isClear: boolean;
  tag: string | null;
  sub: AiWatermarkSubThreat | null;
  positions: number[];
}

export interface AiWatermarkContext {
  zwspModuloTolerance?: number;
  adversarialTolerance?: number;
}

export interface AiWatermarkVerdict {
  input: number[];
  classify: AiWatermarkClassification;
  markerCount: number;
}

export declare function aiWatermarkDetectabilityReasonCode(subThreatTag: string): string;
export declare function aiWatermarkSubThreatTag(sub: AiWatermarkSubThreat): string;
export declare function aiWatermarkCueClass(sub: AiWatermarkSubThreat): CueClass | null;
export declare function aiWatermarkDetectabilityDetect(input: number[]): AiWatermarkVerdict;
export declare function aiWatermarkDetectabilityDetectWithContext(
  ctx: AiWatermarkContext,
  input: number[],
): AiWatermarkVerdict;

// ── emoji-zwj-integrity (identity-layer detector I3) ─────────────────────────

export declare const MAX_RGI_LENGTH: 16;
export declare const EMOJI_ZWJ: 0x200d;

export type EmojiZwjSubThreat =
  | { kind: "DoubleZwj"; positions: number[] }
  | { kind: "NonEmojiInjection"; zwjPos: number; nonEmojiCp: number }
  | { kind: "OverLength"; length: number; maxLength: number }
  | { kind: "SkinToneOverflow"; count: number }
  | { kind: "UnregisteredSequence"; chainLen: number };

export interface EmojiZwjClassification {
  isClear: boolean;
  tag: string | null;
  sub: EmojiZwjSubThreat | null;
  positions: number[];
}

export interface EmojiZwjVerdict {
  input: number[];
  classify: EmojiZwjClassification;
  zwjPositions: number[];
  chainLength: number;
  isRegisteredRgi: boolean;
  skinToneCount: number;
}

export declare function emojiZwjIntegrityReasonCode(subThreatTag: string): string;
export declare function emojiZwjSubThreatTag(sub: EmojiZwjSubThreat): string;
export declare function isRegisteredZwjSequence(cps: Iterable<number>): boolean;
export declare function isEmojiTarget(cp: number): boolean;
export declare function isEmojiModifier(cp: number): boolean;
export declare function emojiZwjIntegrityDetect(input: number[]): EmojiZwjVerdict;

// ── renderer-divergence (layer D) ────────────────────────────────────────────

export declare const MIN_COMBINING_STACK: 4;

export type RendererDivergenceSubThreat =
  | { kind: "CombiningStackOverflow"; basePos: number; stackLen: number }
  | { kind: "VariationSelectorVariance"; firstVsPos: number; firstVsCp: number }
  | { kind: "UnregisteredZwjVariance"; firstZwjPos: number }
  | { kind: "FullwidthVariance"; firstFwPos: number; firstFwCp: number }
  | { kind: "MixedDirectionVariance"; ltrCount: number; rtlCount: number };

export interface RendererDivergenceClassification {
  isClear: boolean;
  tag: string | null;
  sub: RendererDivergenceSubThreat | null;
  positions: number[];
}

export interface RendererDivergenceVerdict {
  input: number[];
  classify: RendererDivergenceClassification;
  vsCount: number;
  combiningCount: number;
  fullwidthCount: number;
  hasZwj: boolean;
  strongLtrCount: number;
  strongRtlCount: number;
}

export declare function rendererDivergenceReasonCode(subThreatTag: string): string;
export declare function rendererDivergenceSubThreatTag(sub: RendererDivergenceSubThreat): string;
export declare function rendererDivergenceDetect(input: number[]): RendererDivergenceVerdict;

// ── filename-disguise (layer D) ──────────────────────────────────────────────

export type FilenameDisguiseSubThreat =
  | { kind: "RloFlip"; position: number; controlCp: number }
  | { kind: "WidthClassExt"; position: number; cp: number }
  | { kind: "CombiningInExt"; position: number; cp: number }
  | { kind: "MultipleExtensions"; dotCount: number };

export interface FilenameDisguiseClassification {
  isClear: boolean;
  tag: string | null;
  sub: FilenameDisguiseSubThreat | null;
  positions: number[];
}

export interface FilenameDisguiseVerdict {
  input: number[];
  classify: FilenameDisguiseClassification;
  dotPositions: number[];
  lastDotPos: number | null;
  bidiControlCount: number;
  fullwidthInExt: number;
  combiningInExt: number;
}

export declare function filenameDisguiseReasonCode(subThreatTag: string): string;
export declare function filenameDisguiseSubThreatTag(sub: FilenameDisguiseSubThreat): string;
export declare function filenameDisguiseDetect(input: number[]): FilenameDisguiseVerdict;

// ── source-display-divergence (layer D, aggregator) ──────────────────────────

export type SourceDisplayDivergenceSubThreat =
  | { kind: "TagBlock" }
  | { kind: "VariationSelector" }
  | { kind: "ZeroWidth" }
  | { kind: "BidiControl" }
  | { kind: "IdentifierHomoglyph" }
  | { kind: "Compound" };

export interface SourceDisplayDivergenceClassification {
  isClear: boolean;
  tag: string | null;
  sub: SourceDisplayDivergenceSubThreat | null;
  positions: number[];
}

export interface SourceDisplayDivergenceVerdict {
  input: number[];
  classify: SourceDisplayDivergenceClassification;
  fired: string[];
}

export declare function sourceDisplayDivergenceReasonCode(subThreatTag: string): string;
export declare function sourceDisplayDivergenceSubThreatTag(
  sub: SourceDisplayDivergenceSubThreat,
): string;
export declare function sourceDisplayDivergenceDetect(
  input: number[],
): SourceDisplayDivergenceVerdict;

// ── identifier-form-drift (layer X) ──────────────────────────────────────────

export type IdentifierFormDriftSubThreat = {
  kind: "IdentifierStatusShift";
  basePos: number;
  cp: number;
};

export interface IdentifierFormDriftClassification {
  isClear: boolean;
  tag: string | null;
  sub: IdentifierFormDriftSubThreat | null;
  positions: number[];
}

export interface IdentifierFormDriftVerdict {
  input: number[];
  classify: IdentifierFormDriftClassification;
  shiftCount: number;
}

export declare function identifierFormDriftReasonCode(subThreatTag: string): string;
export declare function identifierFormDriftSubThreatTag(
  sub: IdentifierFormDriftSubThreat,
): string;
export declare function identifierFormDriftDetect(input: number[]): IdentifierFormDriftVerdict;

// ── admissibility-form-drift (layer X) ───────────────────────────────────────

export type AdmissibilityFormDriftSubThreat = {
  kind: "AdmissibilityFormDrift";
  inputAdmissible: boolean;
  nfkcAdmissible: boolean;
};

export interface AdmissibilityFormDriftClassification {
  isClear: boolean;
  tag: string | null;
  sub: AdmissibilityFormDriftSubThreat | null;
  positions: number[];
}

export interface AdmissibilityFormDriftVerdict {
  input: number[];
  classify: AdmissibilityFormDriftClassification;
  inputAdmissible: boolean;
  nfkcAdmissible: boolean;
}

export declare function admissibilityFormDriftReasonCode(subThreatTag: string): string;
export declare function admissibilityFormDriftSubThreatTag(
  sub: AdmissibilityFormDriftSubThreat,
): string;
export declare function admissibilityFormDriftDetect(
  input: number[],
): AdmissibilityFormDriftVerdict;

// ── case-expansion-mismatch (layer F) ────────────────────────────────────────

export type CaseExpansionMismatchSubThreat =
  | { kind: "UpperExpansion"; basePos: number; cp: number; expansionLen: number }
  | { kind: "LowerExpansion"; basePos: number; cp: number; expansionLen: number };

export interface CaseExpansionMismatchClassification {
  isClear: boolean;
  tag: string | null;
  sub: CaseExpansionMismatchSubThreat | null;
  positions: number[];
}

export interface CaseExpansionMismatchVerdict {
  input: number[];
  classify: CaseExpansionMismatchClassification;
  upperExpansionCount: number;
  lowerExpansionCount: number;
  maxExpansionLen: number;
}

export declare function caseExpansionMismatchReasonCode(subThreatTag: string): string;
export declare function caseExpansionMismatchSubThreatTag(
  sub: CaseExpansionMismatchSubThreat,
): string;
export declare function caseExpansionMismatchDetect(
  input: number[],
): CaseExpansionMismatchVerdict;

// ── skin-tone-variation-forgery (layer I) ────────────────────────────────────

export type SkinToneVariationForgerySubThreat =
  | { kind: "StackedSkinTones"; basePos: number; modifiers: number[] }
  | { kind: "InvalidSkinToneTarget"; basePos: number; baseCp: number; modifierCp: number }
  | { kind: "ForcedTextStyle"; basePos: number; baseCp: number };

export interface SkinToneVariationForgeryClassification {
  isClear: boolean;
  tag: string | null;
  sub: SkinToneVariationForgerySubThreat | null;
  positions: number[];
}

export interface SkinToneVariationForgeryVerdict {
  input: number[];
  classify: SkinToneVariationForgeryClassification;
  skinToneCount: number;
  variationSelector15Count: number;
  variationSelector16Count: number;
}

export declare function isSkinToneBase(cp: number): boolean;
export declare function isEmojiPresentation(cp: number): boolean;
export declare function skinToneVariationForgeryReasonCode(subThreatTag: string): string;
export declare function skinToneVariationForgerySubThreatTag(
  sub: SkinToneVariationForgerySubThreat,
): string;
export declare function skinToneVariationForgeryDetect(
  input: number[],
): SkinToneVariationForgeryVerdict;

// ── stream-safe-violation (layer F) ─────────────────────────────────────────

export declare const STREAM_SAFE_LIMIT: 30;
export declare function streamSafeViolationReasonCode(subThreatTag: string): string;

export type StreamSafeSubThreat = { kind: "StreamSafeOverrun"; basePos: number; runLen: number };

export interface StreamSafeClassification {
  isClear: boolean;
  tag: string | null;
  sub: StreamSafeSubThreat | null;
  positions: number[];
}

export interface StreamSafeVerdict {
  input: number[];
  classify: StreamSafeClassification;
  maxRunLen: number;
  overrunCount: number;
  totalNonStarters: number;
}

export declare function streamSafeViolationDetect(input: number[]): StreamSafeVerdict;
