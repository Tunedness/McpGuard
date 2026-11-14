/**
 * `guardlock.json` on disk: where it is, how it is read, how it is written.
 *
 * The lock goes into version control (ADR-005), so it is serialised the same
 * way every time, and it is written by renaming a finished file into place: a
 * crash mid-write leaves the old lock or the new one, never half of either.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { type GuardLock, LockFormatError, parseLock, serializeLock } from '@mcpguard/core';
import { messageOf } from './errors.js';

/** What reading the lock found. */
export type LockState =
  | { readonly kind: 'absent' }
  | { readonly kind: 'ok'; readonly lock: GuardLock }
  /** The file exists and cannot be trusted. Never overwritten by a first-use write. */
  | { readonly kind: 'invalid'; readonly reason: string };

/** The lock's storage, as the manifest gate and the `lock` command see it. */
export interface LockStore {
  readonly path: string;
  read(): LockState;
  write(lock: GuardLock): void;
}

/** A {@link LockStore} over a real file. */
export function fileLockStore(path: string): LockStore {
  return {
    path,
    read: () => {
      let text: string;
      try {
        text = readFileSync(path, 'utf8');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' };
        return { kind: 'invalid', reason: `cannot read: ${messageOf(error)}` };
      }
      try {
        return { kind: 'ok', lock: parseLock(text) };
      } catch (error) {
        const reason = error instanceof LockFormatError ? error.message : messageOf(error);
        return { kind: 'invalid', reason };
      }
    },
    write: (lock) => {
      mkdirSync(dirname(path), { recursive: true });
      const temporary = join(
        dirname(path),
        `.${basename(path)}.${randomBytes(6).toString('hex')}.tmp`,
      );
      try {
        writeFileSync(temporary, serializeLock(lock), { flag: 'wx' });
        renameSync(temporary, path);
      } catch (error) {
        rmSync(temporary, { force: true });
        throw error;
      }
    },
  };
}
