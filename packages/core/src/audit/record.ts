/**
 * The audit record, and the hash chain that makes it tamper-evident.
 *
 * Every record carries the hash of the one before it, so altering a record in
 * the middle of the file breaks every hash after it. Building a record and
 * verifying the chain are pure computation and live here; writing the file is
 * the CLI's job (ADR-004).
 *
 * The record never holds raw content. It holds the **masked** content plus a
 * keyed fingerprint of the raw bytes — a plain digest of low-entropy content
 * would be a recovery path, which is the whole point of ADR-004's 2026-09-16
 * amendment. Integrity and de-duplication still work; brute-forcing the value
 * back does not.
 */
import { hmacSha256, sha256 } from '../util/hash.js';
import { stableStringify, toJsonValue } from '../util/json.js';

/** What a record is about. */
export type AuditKind = 'tool_call' | 'resource_read' | 'tool_list' | 'access_denied';

/** The fields a caller supplies; the chain fields are computed. */
export interface AuditFields {
  readonly at: number;
  readonly sessionId: string;
  readonly kind: AuditKind;
  readonly serverName: string;
  readonly toolName: string | undefined;
  /** The action taken: allow / flag / strip / block / deny. */
  readonly action: string;
  /** 0–100 injection score, when the scanner produced one. */
  readonly score: number | undefined;
  /** Rule and recogniser ids only. Never content. */
  readonly findings: readonly string[];
  /** PII recogniser kinds that fired. */
  readonly piiKinds: readonly string[];
  /** The masked content that was forwarded, capped for the log. */
  readonly maskedContent: string;
  /** Whether the session id was resolved exactly or inferred (ADR-006). */
  readonly sessionExact: boolean;
}

/** A complete, chained record. */
export interface AuditRecord extends AuditFields {
  readonly seq: number;
  /** Keyed fingerprint of the raw content, or absent when no key is set. */
  readonly contentFingerprint?: string;
  /** The hash of the previous record; the genesis link is 64 zeros. */
  readonly prevHash: string;
  /** This record's hash, over its content and `prevHash`. */
  readonly hash: string;
}

/** The genesis link: what the first record points back at. */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * Builds the next record in a chain.
 *
 * `rawContent` is fingerprinted with the key and then dropped — it is never
 * stored. Absent key means no fingerprint, which is a weaker trail than a keyed
 * one and still better than a plain digest of low-entropy content.
 */
export function buildRecord(
  seq: number,
  prevHash: string,
  fields: AuditFields,
  rawContent: string,
  auditKey: string | undefined,
): AuditRecord {
  const fingerprint = auditKey === undefined ? undefined : hmacSha256(auditKey, rawContent);
  const body = {
    seq,
    ...fields,
    ...(fingerprint !== undefined ? { contentFingerprint: fingerprint } : {}),
    prevHash,
  };
  const hash = sha256(stableStringify(toJsonValue(body)));
  return { ...body, hash };
}

/** Serialises a record to one JSONL line. */
export function serializeRecord(record: AuditRecord): string {
  return `${JSON.stringify(record)}\n`;
}
