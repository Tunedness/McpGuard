/**
 * `@tunedness/mcpguard-ruleset` — the detection ruleset, as data.
 *
 * ADR-003 keeps the rules out of the code and versions them separately, so an
 * answer to a new attack shape ships without an engine release. This module is
 * the smallest possible seam: it reads the JSON files that sit next to it and
 * hands back one plain object, in the shape `@tunedness/mcpguard-detect` validates,
 * digests and compiles. Nothing here is executed by the engine; it is data.
 *
 * The package declares no npm dependencies. `node:fs` is a builtin, and reading
 * the files at load — rather than importing them — keeps the JSON out of the
 * compiled output and lets the engine own validation, where it belongs.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Version of the ruleset data. Recorded in every verdict and audit record. */
export const RULESET_VERSION = '0.1.0';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function readJson(relative: string): unknown {
  return JSON.parse(readFileSync(join(ROOT, relative), 'utf8'));
}

/**
 * The ruleset document, assembled from the data files.
 *
 * Typed as `unknown`: the engine's `loadRuleset` is the one authority on whether
 * it is valid, and duplicating that judgement here would be a second place for
 * the shape to drift.
 */
export function loadRulesetData(): unknown {
  const manifest = readJson('index.json') as {
    rulesetVersion: string;
    engineRange: string;
    locales: string[];
    files: Record<string, string>;
  };
  return {
    schemaVersion: 1,
    rulesetVersion: manifest.rulesetVersion,
    engineRange: manifest.engineRange,
    locales: manifest.locales,
    rules: readJson(manifest.files.rules ?? ''),
    lexicons: {
      verbsEn: readJson(manifest.files.verbsEn ?? ''),
      verbsTr: readJson(manifest.files.verbsTr ?? ''),
      benignImperatives: readJson(manifest.files.benignImperatives ?? ''),
    },
    pii: loadPii(manifest.files),
  };
}

/** One locale's PII keyword file. Every list may be empty; the merged one may not. */
interface PiiContextFile {
  anchors: { health_ref: string[] };
  context: { health_date: string[]; ssn_us: string[]; icd10: string[]; gs1_serial: string[] };
  exclude: { health_ref: string[]; health_date: string[] };
  strong: { health_ref: string[]; health_date: string[] };
  profileContext: { tckn: string[]; phone: string[] };
}

/**
 * The PII section: the profile membership and the per-locale keyword files,
 * merged Turkish first then English. Keywords are data, never patterns — the
 * engine tokenises them and compares text.
 */
function loadPii(files: Record<string, string>): unknown {
  const tr = readJson(files.piiContextTr ?? '') as PiiContextFile;
  const en = readJson(files.piiContextEn ?? '') as PiiContextFile;
  return {
    profiles: readJson(files.piiProfiles ?? ''),
    anchors: { health_ref: [...tr.anchors.health_ref, ...en.anchors.health_ref] },
    context: {
      health_date: [...tr.context.health_date, ...en.context.health_date],
      ssn_us: [...tr.context.ssn_us, ...en.context.ssn_us],
      icd10: [...tr.context.icd10, ...en.context.icd10],
      gs1_serial: [...tr.context.gs1_serial, ...en.context.gs1_serial],
    },
    exclude: {
      health_ref: [...tr.exclude.health_ref, ...en.exclude.health_ref],
      health_date: [...tr.exclude.health_date, ...en.exclude.health_date],
    },
    strong: {
      health_ref: [...tr.strong.health_ref, ...en.strong.health_ref],
      health_date: [...tr.strong.health_date, ...en.strong.health_date],
    },
    profileContext: {
      tckn: [...tr.profileContext.tckn, ...en.profileContext.tckn],
      phone: [...tr.profileContext.phone, ...en.profileContext.phone],
    },
  };
}
