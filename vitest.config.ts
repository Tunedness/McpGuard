import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Vitest 5 replaced the standalone `vitest.workspace.ts` file with this
    // `test.projects` array. Each entry is a directory containing a
    // package.json; the package name becomes the project name in the reporter.
    projects: ['packages/*', 'bench'],
    coverage: {
      // On by default, so `npm test` is the gate rather than a separate command
      // somebody remembers to run.
      enabled: true,
      provider: 'v8',
      reporter: ['text', 'lcov'],
      reportsDirectory: 'coverage',
      include: ['packages/*/src/**/*.ts'],
      // `src/testing/` holds harnesses and scenario doubles: test scaffolding
      // that happens not to end in `.test.ts`. It is excluded from the package
      // builds too, so it never ships.
      exclude: ['**/*.test.ts', '**/dist/**', 'packages/*/src/testing/**'],
      // The two pure packages are the whole product's safety net. If the
      // scanner's verdict or the engine's decision is wrong, either a working
      // agent is stopped or a poisoned tool result reaches the model. The gate
      // is deliberately only on those two — the proxy and the CLI are thin, and
      // padding their numbers would tell nobody anything.
      thresholds: {
        'packages/core/src/**': { lines: 90, functions: 90, branches: 90, statements: 90 },
        'packages/detect/src/**': { lines: 90, functions: 90, branches: 90, statements: 90 },
      },
    },
  },
});
