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
