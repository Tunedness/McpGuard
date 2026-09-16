import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { defaultPolicy } from './policy/index.js';

/**
 * The committed JSON Schema, checked for the two things `schema:check` cannot
 * say: that it is actually committed, and that it describes the shape a person
 * writes rather than the shape the engine ends up with.
 */

const SCHEMA_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'schemas',
  'guardpolicy.v1.schema.json',
);

const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8')) as {
  $id: string;
  properties: Record<string, { default?: unknown; enum?: string[] }>;
};

describe('guardpolicy.v1.schema.json', () => {
  it('is committed and carries the published id', () => {
    expect(schema.$id).toBe('https://schemas.tunedness.com/mcpguard/guardpolicy.v1.schema.json');
  });

  it('describes the input shape, so a duration is still writable as `10m`', () => {
    // Generating the *output* shape would produce a schema that rejects every
    // duration a person would actually type.
    const session = schema.properties.session as { properties?: Record<string, unknown> };
    expect(JSON.stringify(session)).toContain('ms|s|m|h|d');
  });

  it('agrees with the engine about the default posture', () => {
    // Two representations of one decision. If they drift, the one an operator
    // reads and the one that runs are different documents.
    expect(schema.properties.mode?.default).toBe(defaultPolicy().mode);
    expect(schema.properties.mode?.enum).toEqual(['flag', 'enforce']);
  });
});
