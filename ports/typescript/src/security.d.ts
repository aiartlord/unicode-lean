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
