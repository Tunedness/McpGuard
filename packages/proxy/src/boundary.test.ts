import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The boundary that keeps the transport skeleton liftable.
 *
 * Four files are kept free of both engine packages, so the day McpGuard and its
 * sibling share a transport package is a move rather than a rewrite. This test
 * fails the build if any of them imports an engine, and pins the exact set of
 * files that are *allowed* to — so a fifth engine-aware file is a decision, not
 * an accident.
 *
 * It also pins stdout discipline: in wrap mode stdout is the agent's JSON-RPC
 * stream, and a single `console.log` in a shared module corrupts every frame
 * after it.
 */

const SRC = dirname(fileURLToPath(import.meta.url));
const SPECIFIER_RE =
  /(?:\bfrom\s*|^\s*import\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)['"]([^'"]+)['"]/gm;

/** The files that must never import an engine. */
const ENGINE_FREE = [
  'bridge.ts',
  'era.ts',
  'remap.ts',
  'diagnostics.ts',
  'stdio-wrap.ts',
  'content.ts',
];
/** The files that are allowed to import an engine — the exact set. */
const ENGINE_AWARE = ['guard.ts'];

function read(name: string): string {
  return readFileSync(join(SRC, name), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

function specifiers(code: string): string[] {
  const out: string[] = [];
  for (const match of code.matchAll(SPECIFIER_RE)) if (match[1] !== undefined) out.push(match[1]);
  return out;
}

function importsEngine(code: string): boolean {
  return specifiers(code).some((s) => s === '@mcpguard/core' || s === '@mcpguard/detect');
}

describe('proxy boundary', () => {
  it.each(ENGINE_FREE)('%s imports no engine package', (name) => {
    expect(importsEngine(read(name))).toBe(false);
  });

  it('every engine-free file still exists, so the list cannot rot', () => {
    for (const name of ENGINE_FREE) {
      expect(() => read(name)).not.toThrow();
    }
  });

  it('pins the exact set of files that import an engine', () => {
    const sources = readdirSync(SRC).filter(
      (f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && f !== 'index.ts' && f !== 'version.ts',
    );
    const aware = sources.filter((f) => importsEngine(read(f))).sort();
    // A fifth engine-aware file is one more thing the sibling cannot lift; adding
    // it is a decision that updates this list, not a silent change.
    expect(aware).toEqual(ENGINE_AWARE);
  });

  it('no source file touches stdout or console', () => {
    const sources = readdirSync(SRC).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'));
    for (const name of sources) {
      const code = read(name);
      expect(code).not.toMatch(/\bconsole\./);
      expect(code).not.toMatch(/process\.stdout/);
    }
  });
});
