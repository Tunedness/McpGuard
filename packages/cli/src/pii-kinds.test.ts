import { PII_RECOGNIZER_IDS } from '@tunedness/mcpguard-core';
import { PII_KINDS } from '@tunedness/mcpguard-detect';
import { describe, expect, it } from 'vitest';

/**
 * The policy schema lists the recogniser ids a policy may name, and cannot
 * import the engine's list — `@tunedness/mcpguard-core` does not depend on
 * `@tunedness/mcpguard-detect`. This is the one place both are in reach, so it
 * is where they are held equal: an id added to one and not the other would be
 * either unreachable from a policy or accepted by it and ignored.
 */
describe('recogniser ids', () => {
  it('are the same list in the policy schema and in the engine', () => {
    expect([...PII_RECOGNIZER_IDS]).toEqual([...PII_KINDS]);
  });
});
