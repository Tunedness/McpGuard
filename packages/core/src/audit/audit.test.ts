import { describe, expect, it } from 'vitest';
import { checkpointOf, matchesCheckpoint, verifyChain } from './chain.js';
import { type AuditFields, type AuditRecord, buildRecord, GENESIS_HASH } from './record.js';

/**
 * The tamper-evidence claim, tested by tampering. A hash chain is only worth
 * anything if a changed record is detectable and a swapped file is too.
 */

function fields(seq: number): AuditFields {
  return {
    at: 1_000 + seq,
    sessionId: 'sess-1',
    kind: 'tool_call',
    serverName: 'github',
    toolName: 'get_issue',
    action: 'allow',
    score: 0,
    findings: [],
    piiKinds: [],
    maskedContent: `result ${seq}`,
    sessionExact: true,
  };
}

/** Builds a chain of `n` records, each fingerprinting its own raw content. */
function chain(n: number, key = 'audit-key'): AuditRecord[] {
  const records: AuditRecord[] = [];
  let prev = GENESIS_HASH;
  for (let seq = 0; seq < n; seq++) {
    const record = buildRecord(seq, prev, fields(seq), `raw ${seq}`, key);
    records.push(record);
    prev = record.hash;
  }
  return records;
}

describe('buildRecord', () => {
  it('fingerprints the raw content with the key instead of storing it', () => {
    const record = buildRecord(0, GENESIS_HASH, fields(0), '10000000146', 'k');

    expect(record.contentFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(record)).not.toContain('10000000146');
  });

  it('omits the fingerprint when no key is configured', () => {
    const record = buildRecord(0, GENESIS_HASH, fields(0), 'raw', undefined);

    expect(record.contentFingerprint).toBeUndefined();
  });

  it('links to the previous record', () => {
    const [a, b] = chain(2);
    expect(b?.prevHash).toBe(a?.hash);
  });
});

describe('caller identity on a record', () => {
  const identity = { identity: 'alice', source: 'flag', exact: true } as const;

  it('is part of the hashed body, so altering it breaks the chain', () => {
    const record = buildRecord(
      0,
      GENESIS_HASH,
      { ...fields(0), callerIdentity: identity },
      'raw',
      'k',
    );
    expect(verifyChain([record]).ok).toBe(true);

    const forged = { ...record, callerIdentity: { ...identity, exact: false } };
    expect(verifyChain([forged]).ok).toBe(false);
  });

  it('leaves a record written before the ladder existed verifiable', () => {
    // No callerIdentity key at all: what every v0.1.0 log holds.
    const legacy = buildRecord(0, GENESIS_HASH, fields(0), 'raw', 'k');
    expect('callerIdentity' in legacy).toBe(false);

    const next = buildRecord(
      1,
      legacy.hash,
      { ...fields(1), callerIdentity: identity },
      'raw',
      'k',
    );
    expect(verifyChain([legacy, next]).ok).toBe(true);
  });

  it('survives a JSON round trip, as the log is read back from disk', () => {
    const none = { identity: undefined, source: 'none', exact: false } as const;
    const record = buildRecord(0, GENESIS_HASH, { ...fields(0), callerIdentity: none }, 'raw', 'k');
    const read = JSON.parse(JSON.stringify(record)) as AuditRecord;

    expect(verifyChain([read]).ok).toBe(true);
  });
});

describe('session source on a record (ADR-006)', () => {
  it('is part of the hashed body, so a guess cannot be rewritten as an exact answer', () => {
    const record = buildRecord(
      0,
      GENESIS_HASH,
      { ...fields(0), sessionSource: 'client-address', sessionExact: false },
      'raw',
      'k',
    );
    expect(verifyChain([record]).ok).toBe(true);
    expect(verifyChain([{ ...record, sessionSource: 'traceparent' }]).ok).toBe(false);
    expect(verifyChain([{ ...record, sessionExact: true }]).ok).toBe(false);
  });

  it('leaves a record written before the field existed verifiable, alongside one that has it', () => {
    const before = buildRecord(0, GENESIS_HASH, fields(0), 'raw', 'k');
    expect('sessionSource' in before).toBe(false);
    const after = buildRecord(
      1,
      before.hash,
      { ...fields(1), sessionSource: 'connection' },
      'raw',
      'k',
    );
    const read = JSON.parse(JSON.stringify([before, after])) as AuditRecord[];
    expect(verifyChain(read).ok).toBe(true);
  });
});

describe('verifyChain', () => {
  it('accepts an intact chain', () => {
    expect(verifyChain(chain(5)).ok).toBe(true);
  });

  it('catches a record altered in the middle', () => {
    const records = chain(5);
    // Rewrite the masked content of record 2 without recomputing anything.
    const tampered = records.map((r) => (r.seq === 2 ? { ...r, maskedContent: 'doctored' } : r));
    const result = verifyChain(tampered);

    expect(result.ok).toBe(false);
    expect(result.brokeAt).toBe(2);
    expect(result.reason).toBe('record altered');
  });

  it('catches a record removed from the middle', () => {
    const records = chain(5).filter((r) => r.seq !== 2);
    const result = verifyChain(records);

    expect(result.ok).toBe(false);
    // The record that was seq 3 now sits where seq 2 was expected.
    expect(result.reason).toBe('sequence gap');
  });

  it('catches a re-linked record whose prevHash was forged', () => {
    const records = chain(3);
    const forged = records.map((r) => (r.seq === 1 ? { ...r, prevHash: GENESIS_HASH } : r));

    expect(verifyChain(forged).reason).toBe('broken link');
  });
});

describe('checkpoints', () => {
  it('matches a checkpoint taken from the same chain', () => {
    const records = chain(4);
    const checkpoint = checkpointOf(records.slice(0, 3));

    expect(matchesCheckpoint(records, checkpoint)).toBe(true);
  });

  it('does not match after the file is swapped wholesale', () => {
    const original = chain(4);
    const checkpoint = checkpointOf(original.slice(0, 3));
    // A different, internally-consistent chain: verifies on its own, but the
    // checkpoint from the original does not vouch for it.
    const swapped = chain(4, 'different-key');

    expect(verifyChain(swapped).ok).toBe(true);
    expect(matchesCheckpoint(swapped, checkpoint)).toBe(false);
  });
});
