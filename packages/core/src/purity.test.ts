import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The invariant the whole auditability claim rests on.
 *
 * `@mcpguard/core` decides whether a call is permitted and what an audit record
 * says. If that decision can read a clock, a file, an environment variable or a
 * socket, then a decision made six months ago cannot be reproduced by whoever
 * is auditing it today — and "tamper-evident audit log" becomes a sentence
 * about file formats rather than about evidence.
 *
 * So this test walks every non-test source file in the package and fails on
 * anything that would let ambient state in. **It is not to be relaxed to reach
 * green.** If a new module needs something on this list, the module is wrong.
 */

const SRC = dirname(fileURLToPath(import.meta.url));

/** Matches an import specifier in any of the four forms TypeScript allows. */
const SPECIFIER_RE =
  /(?:\bfrom\s*|^\s*import\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)['"]([^'"]+)['"]/gm;

const FORBIDDEN_PACKAGES = [
  '@modelcontextprotocol/',
  '@mcpguard/detect',
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

describe('@mcpguard/core purity', () => {
  it('has source files to check, so an empty walk cannot pass silently', () => {
    expect(FILES.length).toBeGreaterThan(8);
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

  it('imports exactly one Node builtin across the package, and it is node:crypto', () => {
    // SHA-256 and HMAC are computation. Anything else in `node:` is a way for
    // the outside world to reach in, and the engine has no business with it.
    const builtins = new Set<string>();
    for (const { code } of FILES) {
      for (const specifier of specifiers(code)) {
        if (specifier.startsWith('node:')) builtins.add(specifier);
      }
    }
    expect([...builtins]).toEqual(['node:crypto']);
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
    // A policy is compiled once and then asked questions inside a 20 ms budget
    // shared with a whole content scan. Building a regex per call is how that
    // budget is lost, and it is lost quietly.
    const builders = FILES.filter(({ code }) => /\bnew\s+RegExp\s*\(/.test(code)).map(
      ({ relative }) => relative,
    );
    expect(builders.sort()).toEqual(['policy/glob.ts', 'policy/schema.ts']);
  });
});
