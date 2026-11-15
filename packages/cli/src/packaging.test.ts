/**
 * Version constants must equal the manifests they describe.
 *
 * `CORE_VERSION`, `DETECT_VERSION`, `PROXY_VERSION`, `RULESET_PACKAGE_VERSION`
 * and `CLI_VERSION` are hand-maintained: the pure packages cannot read their own
 * `package.json` (the purity tests forbid the filesystem), and a constant kept
 * next to the code is what ends up in audit records and in `--version`. Nothing
 * in the code keeps the two in step, so this test does: a `changeset version`
 * that bumps a manifest without the constant fails CI instead of publishing a
 * package that reports the wrong version.
 *
 * It reads the constants out of the source files rather than importing them, so
 * the check covers `RULESET_PACKAGE_VERSION` too, which the package does not
 * export.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const PACKAGES = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const CONSTANTS = [
  { pkg: 'cli', file: 'src/index.ts', name: 'CLI_VERSION' },
  { pkg: 'core', file: 'src/version.ts', name: 'CORE_VERSION' },
  { pkg: 'detect', file: 'src/version.ts', name: 'DETECT_VERSION' },
  { pkg: 'proxy', file: 'src/version.ts', name: 'PROXY_VERSION' },
  { pkg: 'ruleset', file: 'src/version.ts', name: 'RULESET_PACKAGE_VERSION' },
] as const;

const NAMES: Record<string, string> = {
  cli: '@tunedness/mcpguard',
  core: '@tunedness/mcpguard-core',
  detect: '@tunedness/mcpguard-detect',
  proxy: '@tunedness/mcpguard-proxy',
  ruleset: '@tunedness/mcpguard-ruleset',
};

interface Manifest {
  name: string;
  version: string;
  bin?: Record<string, string>;
  repository?: { type?: string; url?: string; directory?: string };
  dependencies?: Record<string, string>;
}

function manifest(pkg: string): Manifest {
  return JSON.parse(readFileSync(join(PACKAGES, pkg, 'package.json'), 'utf8'));
}

function parse(version: string): [number, number, number] {
  const [major = 0, minor = 0, patch = 0] = version.split('.').map(Number);
  return [major, minor, patch];
}

/** Whether `version` satisfies an exact (`1.2.3`) or caret (`^1.2.3`) range. */
function satisfies(version: string, range: string): boolean {
  if (!range.startsWith('^')) return version === range;
  const [major, minor, patch] = parse(version);
  const [rMajor, rMinor, rPatch] = parse(range.slice(1));
  if (rMajor > 0)
    return major === rMajor && (minor > rMinor || (minor === rMinor && patch >= rPatch));
  if (rMinor > 0) return major === 0 && minor === rMinor && patch >= rPatch;
  return major === 0 && minor === 0 && patch === rPatch;
}

function constantIn(pkg: string, file: string, name: string): string | undefined {
  const source = readFileSync(join(PACKAGES, pkg, file), 'utf8');
  return new RegExp(`export const ${name} = '([^']+)';`).exec(source)?.[1];
}

describe('version constants match the manifests', () => {
  it.each(CONSTANTS)('$name equals $pkg/package.json', ({ pkg, file, name }) => {
    expect(constantIn(pkg, file, name)).toBe(manifest(pkg).version);
  });

  it.each(Object.entries(NAMES))('%s is published as %s', (pkg, name) => {
    expect(manifest(pkg).name).toBe(name);
  });

  it('the CLI keeps `mcpguard` as its binary name', () => {
    expect(Object.keys(manifest('cli').bin ?? {})).toEqual(['mcpguard']);
  });

  // The shipped ruleset names the engine it was written for, and the engine
  // refuses a ruleset that does not name it. Before 1.0 the minor is the
  // compatibility line, so every minor bump of `detect` needs this moved too.
  it('the shipped ruleset accepts the detect version it ships with', () => {
    const data = JSON.parse(readFileSync(join(PACKAGES, 'ruleset', 'index.json'), 'utf8'));
    expect(satisfies(manifest('detect').version, data.engineRange)).toBe(true);
  });

  // npm rejects a provenance-signed publish whose manifest does not name the
  // repository the build ran in, and the whole release fails at publish time.
  it.each(Object.keys(NAMES))('%s names its repository and directory', (pkg) => {
    expect(manifest(pkg).repository).toEqual({
      type: 'git',
      url: 'git+https://github.com/Tunedness/McpGuard.git',
      directory: `packages/${pkg}`,
    });
  });

  // `changeset version` rewrites a real range and skips `*`, so a `*` would
  // publish a package that takes whatever sibling version is newest on the day
  // it is installed.
  describe('internal dependencies', () => {
    const published = new Map(Object.entries(NAMES).map(([pkg, name]) => [name, pkg]));
    const edges = Object.keys(NAMES).flatMap((pkg) =>
      Object.entries(manifest(pkg).dependencies ?? {})
        .filter(([dep]) => published.has(dep))
        .map(([dep, range]) => ({ pkg, dep, range })),
    );

    it('finds the internal dependencies it is meant to check', () => {
      expect(edges.length).toBeGreaterThan(0);
    });

    it.each(edges)('$pkg -> $dep ($range) is a real range its sibling satisfies', (edge) => {
      const sibling = manifest(published.get(edge.dep) as string);
      expect(edge.range).toMatch(/^\^?\d+\.\d+\.\d+$/);
      expect(satisfies(sibling.version, edge.range)).toBe(true);
    });

    it('the CLI pins the engine packages it ships with exactly', () => {
      const deps = manifest('cli').dependencies ?? {};
      for (const pkg of ['core', 'detect', 'proxy']) {
        expect(deps[NAMES[pkg] as string]).toBe(manifest(pkg).version);
      }
    });
  });
});
