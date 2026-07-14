import { readFileSync } from "node:fs";

export * from "./security-core.js";
import { configureSecurityDataReader } from "./security-core.js";

configureSecurityDataReader((name) => readFileSync(new URL(`./data/${name}`, import.meta.url), "utf8"));
