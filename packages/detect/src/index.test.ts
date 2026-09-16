import { describe, expect, it } from 'vitest';
import { DETECT_VERSION } from './index.js';

describe('@mcpguard/detect', () => {
  it('states a version a ruleset can be checked against', () => {
    // A ruleset declares an `engineRange`; this is the value it is satisfied
    // against, so it has to be a real semver rather than a label.
    expect(DETECT_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
