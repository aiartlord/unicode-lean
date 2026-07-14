import {
  Action,
  Family,
  Mode,
  Profile,
  configureSecurityData,
  configureSecurityDataReader,
  scan,
  scanUtf8,
  scanUtf16BE,
  scanUtf16LE,
  scanUtf32BE,
  scanUtf32LE,
  scanUTF8,
  scanUTF16BE,
  scanUTF16LE,
  scanUTF32BE,
  scanUTF32LE,
  verdictJSON,
  verdictJson,
  verdictToWire,
} from "./security-core.js";

export {
  Action,
  Family,
  Mode,
  Profile,
  configureSecurityData,
  configureSecurityDataReader,
  scan,
  scanUtf8,
  scanUtf16BE,
  scanUtf16LE,
  scanUtf32BE,
  scanUtf32LE,
  scanUTF8,
  scanUTF16BE,
  scanUTF16LE,
  scanUTF32BE,
  scanUTF32LE,
  verdictJSON,
  verdictJson,
  verdictToWire,
};

export async function instantiateSecurity(options = {}) {
  if (options.data != null) {
    configureSecurityData(options.data);
  } else if (options.reader != null) {
    configureSecurityDataReader(options.reader);
  } else {
    const baseUrl = options.baseUrl ?? import.meta.url;
    const [confusables, knownAttackTargets] = await Promise.all([
      fetchText(new URL("./data/confusables.txt", baseUrl)),
      fetchText(new URL("./data/KnownAttackTargets.txt", baseUrl)),
    ]);
    configureSecurityData({ confusables, knownAttackTargets });
  }

  return {
    scan,
    scanUtf8,
    scanUtf16BE,
    scanUtf16LE,
    scanUtf32BE,
    scanUtf32LE,
    verdictJson,
    verdictToWire,
  };
}

async function fetchText(url) {
  if (typeof fetch !== "function") {
    throw new Error("fetch is unavailable; pass data or reader to instantiateSecurity");
  }
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`failed to load Unicode security data: ${url}`);
  }
  return response.text();
}
