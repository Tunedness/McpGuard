/**
 * Generates `schemas/guardpolicy.v1.schema.json` from the zod object.
 *
 * The zod object is the single source of truth; this file is what an editor
 * validates against. When the two disagree, a policy that looks valid while
 * being typed gets rejected at startup — which is a bad enough experience on
 * its own, and a genuinely dangerous one for a file whose whole job is to say
 * what the proxy blocks. `--check` makes CI fail on that drift.
 *
 * Run through Node's native type stripping, so it needs no build step of its
 * own and cannot fall behind the package it documents.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { GuardPolicySchemaV1 } from '../dist/policy/schema.js';

const here = dirname(fileURLToPath(import.meta.url));
const target = join(here, '..', 'schemas', 'guardpolicy.v1.schema.json');

// `io: 'input'` is what an editor needs: the shape a person *writes*, before
// defaults are applied and durations are turned into milliseconds. Generating
// the output shape would produce a schema that rejects `10m`.
const generated = z.toJSONSchema(GuardPolicySchemaV1, { io: 'input' });
const document = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://schemas.tunedness.com/mcpguard/guardpolicy.v1.schema.json',
  ...generated,
};
const serialized = `${JSON.stringify(document, null, 2)}\n`;

if (process.argv.includes('--check')) {
  let current: string;
  try {
    current = readFileSync(target, 'utf8');
  } catch {
    console.error('guardpolicy schema is missing; run `npm run schema:generate`');
    process.exitCode = 1;
    throw new Error('schema missing');
  }
  if (current !== serialized) {
    console.error(
      'guardpolicy schema is out of date with the zod object; run `npm run schema:generate`',
    );
    process.exitCode = 1;
  } else {
    console.log('guardpolicy schema is up to date');
  }
} else {
  writeFileSync(target, serialized);
  console.log(`wrote ${target}`);
}
