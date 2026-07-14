export * from "./security.js";

export interface SecurityData {
  confusables: string;
  knownAttackTargets: string;
}

export interface InstantiateSecurityOptions {
  data?: SecurityData;
  reader?: (name: string) => string;
  baseUrl?: string | URL;
}

export declare function instantiateSecurity(options?: InstantiateSecurityOptions): Promise<{
  scan: typeof import("./security.js").scan;
  scanUtf8: typeof import("./security.js").scanUtf8;
  scanUtf16BE: typeof import("./security.js").scanUtf16BE;
  scanUtf16LE: typeof import("./security.js").scanUtf16LE;
  scanUtf32BE: typeof import("./security.js").scanUtf32BE;
  scanUtf32LE: typeof import("./security.js").scanUtf32LE;
  verdictJson: typeof import("./security.js").verdictJson;
  verdictToWire: typeof import("./security.js").verdictToWire;
}>;
