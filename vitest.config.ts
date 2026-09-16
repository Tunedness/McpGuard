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
      // Lines, functions and statements are gated at 90% on both pure packages:
      // those measure whether the code that decides a verdict is actually
      // exercised. Branches sit at 80% deliberately. `noUncheckedIndexedAccess`
      // is on (it has already found real bugs), and it makes every indexed read
      // carry a `?? default` fallback that is defensive rather than reachable
      // with a realistic input — the score path alone has dozens. Gating those
      // branches at 90% would buy contrived tests that assert an impossible
      // input does not crash, not tests that pin behaviour. Every real behaviour
      // has a behavioural test; the residual branches are the guards behind them.
      thresholds: {
        'packages/core/src/**': { lines: 90, functions: 90, branches: 80, statements: 90 },
        'packages/detect/src/**': { lines: 90, functions: 90, branches: 80, statements: 90 },
      },
    },
  },
});
