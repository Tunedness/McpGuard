import { describe, expect, it } from 'vitest';
import { CORE_VERSION } from './index.js';

describe('@mcpguard/core', () => {
  it('states a version without reading a file to find it', () => {
    // The constant is hand-maintained on purpose: nothing in this package
    // touches the filesystem, and `purity.test.ts` is what holds that line.
    expect(CORE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
