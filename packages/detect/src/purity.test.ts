import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The invariant ADR-009's byte-identical promise rests on.
 *
 * The scanner's verdict has to be the same on every machine that computes it,
 * because the CI gate has no tolerance and because an auditor has to be able to
 * reproduce a six-month-old decision. Ambient state of any kind breaks that,
 * and so would a floating-point score — the sibling tool had to give its own
 * gate a tolerance for exactly that reason, and this tier carries no model, so
 * it does not have to.
 *
 * This test walks every non-test source file and fails on anything that would
 * let ambient state in. **It is not to be relaxed to reach green.** If a new
 * module needs something on this list, the module is wrong.
 */

const SRC = dirname(fileURLToPath(import.meta.url));

/** Matches an import specifier in any of the four forms TypeScript allows. */
const SPECIFIER_RE =
  /(?:\bfrom\s*|^\s*import\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)['"]([^'"]+)['"]/gm;

const FORBIDDEN_PACKAGES = [
  '@modelcontextprotocol/',
  '@mcpguard/core',
  // The ruleset is *data* this package validates and compiles. Importing the
  // package that ships it would make the engine depend on one particular
  // version of the rules, which is the coupling ADR-003 exists to avoid.
  '@mcpguard/ruleset',
  '@mcpguard/proxy',
  'mcpguard',
];

const FORBIDDEN_BUILTINS = [
  'node:fs',
  'node:net',
  'node:child_process',
  'node:http',
  'node:https',
  'node:dns',
  'node:tls',
  'node:dgram',
  'node:worker_threads',
  'node:os',
  'node:process',
  'node:readline',
  'node:cluster',
  'node:v8',
  'node:vm',
  'node:inspector',
  'node:perf_hooks',
];

/** Source files, tests and test scaffolding excluded. */
function sourceFiles(dir: string = SRC): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'testing') continue;
      out.push(...sourceFiles(path));
      continue;
    }
    if (!entry.name.endsWith('.ts')) continue;
    if (entry.name.endsWith('.test.ts')) continue;
    out.push(path);
  }
  return out;
}

/**
 * Removes comments before scanning.
 *
 * Every module in this package explains in prose what it refuses to do, and
 * several of them name `node:fs` and `Date.now()` while doing it. A scanner
 * that cannot tell an explanation from a call would make honest documentation
 * the thing that fails the build.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

function specifiers(source: string): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(SPECIFIER_RE)) {
    const value = match[1];
    if (value !== undefined) out.push(value);
  }
  return out;
}

const FILES = sourceFiles().map((path) => ({
  path,
  relative: path.slice(SRC.length + 1),
  code: stripComments(readFileSync(path, 'utf8')),
}));

describe('@mcpguard/detect purity', () => {
  it('has source files to check, so an empty walk cannot pass silently', () => {
    expect(FILES.length).toBeGreaterThan(4);
  });

  it.each(FILES)('$relative imports no protocol or sibling package', ({ code }) => {
    for (const specifier of specifiers(code)) {
      for (const forbidden of FORBIDDEN_PACKAGES) {
        expect(specifier.startsWith(forbidden)).toBe(false);
      }
    }
  });

  it.each(FILES)('$relative imports no I/O builtin', ({ code }) => {
    for (const specifier of specifiers(code)) {
      expect(FORBIDDEN_BUILTINS).not.toContain(specifier);
    }
  });

  it('imports no Node builtin but node:crypto, and today not even that', () => {
    // SHA-256 is computation, and phase 4 will need it to digest a ruleset.
    // Anything else in `node:` is a way for the outside world to reach in, and
    // the scanner has no business with it. The assertion is written as a subset
    // rather than an equality so it keeps holding on the day crypto arrives.
    const builtins = new Set<string>();
    for (const { code } of FILES) {
      for (const specifier of specifiers(code)) {
        if (specifier.startsWith('node:')) builtins.add(specifier);
      }
    }
    for (const builtin of builtins) expect(builtin).toBe('node:crypto');
  });

  it('declares exactly one runtime dependency, and it is zod', () => {
    const manifest = JSON.parse(readFileSync(join(SRC, '..', 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
    };
    expect(Object.keys(manifest.dependencies ?? {})).toEqual(['zod']);
  });

  it.each(FILES)('$relative reads no ambient time or randomness', ({ code }) => {
    // Time comes from an injected `Clock`, ids from an `IdGenerator`. A replay
    // under a fake clock has to produce the same answer, every time.
    expect(code).not.toMatch(/\bDate\.now\s*\(/);
    expect(code).not.toMatch(/\bnew\s+Date\s*\(/);
    expect(code).not.toMatch(/\bMath\.random\s*\(/);
  });

  it.each(FILES)('$relative uses no timers at all', ({ code }) => {
    // Two consequences fall out for free: the package is deterministic under a
    // fake clock, and no background work in it can hold a process open.
    expect(code).not.toMatch(/\bsetTimeout\s*\(/);
    expect(code).not.toMatch(/\bsetInterval\s*\(/);
    expect(code).not.toMatch(/\bsetImmediate\s*\(/);
    expect(code).not.toMatch(/\bqueueMicrotask\s*\(/);
    expect(code).not.toMatch(/\bperformance\.now\s*\(/);
    expect(code).not.toMatch(/\bprocess\.hrtime\b/);
  });

  it('builds regular expressions in exactly one module', () => {
    // Patterns are compiled once, when the ruleset is loaded. A scan runs inside
    // a budget of roughly 20 ms shared with the rest of the proxy, and building
    // a regex per call is how that budget is lost — quietly, and worse as the
    // ruleset grows.
    const builders = FILES.filter(({ code }) => /\bnew\s+RegExp\s*\(/.test(code)).map(
      ({ relative }) => relative,
    );
    expect(builders.sort()).toEqual(['ruleset/compile.ts']);
  });

  it('keeps floating point off the score path', () => {
    // ADR-009. Weights are integers on a 0-1000 scale and the fold is integer
    // division; a float here is a verdict that differs in its last bit between
    // two machines, which is a verdict that cannot be gated without a tolerance.
    const score = FILES.filter(({ relative }) => relative.startsWith('score/'));
    expect(score.length).toBeGreaterThan(1);
    for (const { code } of score) {
      expect(code).not.toMatch(/\d+\.\d+/);
      expect(code).not.toMatch(/\bparseFloat\b/);
    }
  });
});
