/**
 * `@mcpguard/ruleset` — the detection ruleset, as data.
 *
 * ADR-003 keeps the rules out of the code and versions them separately, so an
 * answer to a new attack shape ships without an engine release. This module is
 * the smallest possible seam: it reads the JSON files that sit next to it and
 * hands back one plain object, in the shape `@mcpguard/detect` validates,
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
  };
}
