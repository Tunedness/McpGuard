/**
 * The append-only JSONL audit writer, and the checkpoint publisher.
 *
 * This is the file side of ADR-004: it owns the hash chain (the running head and
 * the sequence), builds each record chained to the last, appends it, and
 * periodically publishes the head as a checkpoint so a wholesale file swap is
 * caught. The checkpoint never goes to stdout — in wrap mode that is the agent's
 * JSON-RPC stream — so it goes to stderr or syslog.
 */
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { type AuditFields, buildRecord, GENESIS_HASH, serializeRecord } from '@mcpguard/core';
import type { AuditRecorder } from './runtime.js';

/** Where a checkpoint is published. */
export interface CheckpointSink {
  write(chunk: string): unknown;
}

/** How the writer is configured. */
export interface AuditWriterOptions {
  readonly path: string;
  readonly auditKey: string | undefined;
  readonly checkpointEvery: number;
  readonly checkpoint: CheckpointSink | undefined;
  /** Injected so tests can avoid the real filesystem. */
  readonly append?: (path: string, line: string) => void;
  /** The chain head to continue from, when re-opening an existing log. */
  readonly resumeFrom?: { seq: number; head: string } | undefined;
}

/** A JSONL audit writer that chains and checkpoints. */
export class AuditWriter implements AuditRecorder {
  readonly #options: AuditWriterOptions;
  readonly #append: (path: string, line: string) => void;
  #seq: number;
  #head: string;

  constructor(options: AuditWriterOptions) {
    this.#options = options;
    this.#append =
      options.append ??
      ((path, line) => {
        // Create the log's directory on first write rather than requiring the
        // operator to have made `.mcpguard/` themselves — a proxy that refused
        // to start over a missing directory would be a proxy nobody keeps.
        mkdirSync(dirname(path), { recursive: true });
        appendFileSync(path, line);
      });
    this.#seq = options.resumeFrom === undefined ? 0 : options.resumeFrom.seq + 1;
    this.#head = options.resumeFrom?.head ?? GENESIS_HASH;
  }

  record(fields: AuditFields, rawContent: string): void {
    const rec = buildRecord(this.#seq, this.#head, fields, rawContent, this.#options.auditKey);
    this.#append(this.#options.path, serializeRecord(rec));
    this.#head = rec.hash;
    this.#seq++;
    if (this.#options.checkpoint !== undefined && this.#seq % this.#options.checkpointEvery === 0) {
      this.#options.checkpoint.write(
        `[mcpguard] ${JSON.stringify({ event: 'audit_checkpoint', seq: this.#seq - 1, head: this.#head })}\n`,
      );
    }
  }

  /** The current chain head, for a final checkpoint at shutdown. */
  get head(): string {
    return this.#head;
  }

  /** The next sequence number, i.e. how many records have been written. */
  get count(): number {
    return this.#seq;
  }
}
