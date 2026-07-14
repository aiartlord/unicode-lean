export {
  Action,
  Family,
  Mode,
  Profile,
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
} from "./edge.js";

export async function instantiateSecurity() {
  const security = await import("./edge.js");
  return security.instantiateSecurity();
}
