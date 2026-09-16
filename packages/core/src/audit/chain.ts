/**
 * Verifying a chain, and the checkpoint that catches a wholesale swap.
 *
 * The chain catches an edit in the middle of the file: change a record and its
 * hash no longer matches, or the next record's `prevHash` no longer matches it.
 * What the chain alone cannot catch is the whole file being replaced with a
 * different, internally-consistent one — so the running head is published
 * periodically outside the file (stderr or syslog, never stdout in wrap mode),
 * and a verifier compares the file's final head against the last checkpoint.
 */
import { digestsEqual, sha256 } from '../util/hash.js';
import { stableStringify, toJsonValue } from '../util/json.js';
import { type AuditRecord, GENESIS_HASH } from './record.js';

/** Where a chain broke, if it did. */
export interface ChainVerification {
  readonly ok: boolean;
  /** The seq of the first bad record, or `undefined` when the chain is intact. */
  readonly brokeAt: number | undefined;
  readonly reason: string | undefined;
  /** The head hash of the chain as read, for comparison against a checkpoint. */
  readonly head: string;
}

/** Recomputes a record's hash from its stored fields. */
function recomputeHash(record: AuditRecord): string {
  const { hash: _hash, ...body } = record;
  return sha256(stableStringify(toJsonValue(body)));
}

/**
 * Walks a chain and reports the first break.
 *
 * Three things must hold at every step: the record's own hash recomputes, its
 * `prevHash` equals the previous record's hash, and the sequence increments by
 * one. The first that fails names where the log was tampered with.
 */
export function verifyChain(records: readonly AuditRecord[]): ChainVerification {
  let prevHash = GENESIS_HASH;
  let expectedSeq = 0;
  for (const record of records) {
    if (record.seq !== expectedSeq) {
      return { ok: false, brokeAt: record.seq, reason: 'sequence gap', head: prevHash };
    }
    if (!digestsEqual(record.prevHash, prevHash)) {
      return { ok: false, brokeAt: record.seq, reason: 'broken link', head: prevHash };
    }
    if (!digestsEqual(record.hash, recomputeHash(record))) {
      return { ok: false, brokeAt: record.seq, reason: 'record altered', head: prevHash };
    }
    prevHash = record.hash;
    expectedSeq++;
  }
  return { ok: true, brokeAt: undefined, reason: undefined, head: prevHash };
}

/** A checkpoint: the running head and the count it covers. */
export interface Checkpoint {
  readonly seq: number;
  readonly head: string;
}

/** The checkpoint after `records`. */
export function checkpointOf(records: readonly AuditRecord[]): Checkpoint {
  const last = records[records.length - 1];
  return { seq: last?.seq ?? -1, head: last?.hash ?? GENESIS_HASH };
}

/**
 * Whether a chain's head matches a checkpoint taken earlier.
 *
 * A file swapped wholesale verifies internally but will not match a checkpoint
 * that was published from the original, which is the swap the chain alone
 * misses.
 */
export function matchesCheckpoint(
  records: readonly AuditRecord[],
  checkpoint: Checkpoint,
): boolean {
  const record = records[checkpoint.seq];
  return record !== undefined && digestsEqual(record.hash, checkpoint.head);
}
