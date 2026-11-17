import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The hand-over document must not say a decision is open once it is made. These are
 * the sentences that went stale in Faz 22's review: each names a fact the measurements
 * and the user's decisions settled.
 */
const DOC = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
    '..',
    '..',
    'docs',
    'implementation-status.md',
  ),
  'utf8',
);
const START = DOC.indexOf('## Faz 22 ');
const FAZ22 = DOC.slice(START);

describe('docs/implementation-status.md, Faz 22', () => {
  it('has the section to check', () => {
    expect(START).toBeGreaterThan(0);
  });

  it('records the V5 decision instead of calling it open', () => {
    expect(FAZ22).not.toContain('Karar kullanıcıda');
    expect(FAZ22).toContain('varsayılan bant değişmez');
    expect(FAZ22).toContain('`band_from: 0`');
  });

  it('no longer says the real model was not measured, or that reasoning_effort is sent only when set', () => {
    expect(DOC).not.toContain('gerçek modelle ölçülmedi');
    expect(FAZ22).not.toContain('yoksa gönderilmez');
    expect(FAZ22).toContain('`omit`');
  });
});
