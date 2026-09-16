import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The disciplines the CLI keeps, enforced rather than documented.
 *
 * In wrap mode stdout is the agent's JSON-RPC stream, so only `main.ts` may
 * touch the process — every command takes a `CliContext` and returns a code. And
 * the whole workspace stays free of `@opentelemetry/*`: a security proxy's
 * dependency tree should be short enough to audit, and the OTLP exporter is
 * hand-written (ADR-007).
 */

const SRC = dirname(fileURLToPath(import.meta.url));
const ROOT = join(SRC, '..', '..', '..');

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'testing') continue;
      out.push(...sourceFiles(path));
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
      out.push(path);
    }
  }
  return out;
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('CLI process discipline', () => {
  const files = sourceFiles(SRC);

  it.each(files.filter((f) => !f.endsWith('main.ts')))(
    '%s does not touch process.stdout/stderr/exit',
    (file) => {
      const code = stripComments(readFileSync(file, 'utf8'));
      expect(code).not.toMatch(/process\.stdout/);
      expect(code).not.toMatch(/process\.stderr/);
      expect(code).not.toMatch(/process\.exit\b/);
    },
  );

  it('touches process only in main.ts', () => {
    const touchers = files
      .filter((f) => /\bprocess\./.test(stripComments(readFileSync(f, 'utf8'))))
      .map((f) => f.slice(SRC.length + 1));
    expect(touchers).toEqual(['main.ts']);
  });
});

describe('no OpenTelemetry anywhere in the workspace', () => {
  it('is absent from every package manifest', () => {
    for (const dir of readdirSync(join(ROOT, 'packages'))) {
      const manifest = JSON.parse(
        readFileSync(join(ROOT, 'packages', dir, 'package.json'), 'utf8'),
      ) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const deps = { ...manifest.dependencies, ...manifest.devDependencies };
      for (const name of Object.keys(deps)) expect(name.startsWith('@opentelemetry/')).toBe(false);
    }
  });

  it('is not an installed package', () => {
    // `npm ls` is the honest check: a name in the lockfile text can be an
    // uninstalled optional peer, but an installed dependency is a real edge.
    let installed = '';
    try {
      installed = execFileSync('npm', ['ls', '@opentelemetry/api', '--all'], {
        cwd: ROOT,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch (error) {
      // `npm ls` exits non-zero when the package is absent; that is the pass.
      installed = (error as { stdout?: string }).stdout ?? '';
    }
    expect(installed).not.toContain('@opentelemetry/api@');
  });
});
