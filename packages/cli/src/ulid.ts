/**
 * A ULID, for the session id a wrapped connection is identified by.
 *
 * Monotonic and sortable, so records land in order. This lives in the CLI, not
 * the engine: the engine mints no identity of its own (that is what keeps it
 * replayable), and the id is injected into it.
 */
import { randomBytes } from 'node:crypto';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** A 26-character ULID for the given time (defaults to now). */
export function ulid(now: number = Date.now()): string {
  let time = now;
  const timeChars: string[] = [];
  for (let i = 0; i < 10; i++) {
    timeChars.unshift(CROCKFORD[time % 32] as string);
    time = Math.floor(time / 32);
  }
  const random = randomBytes(16);
  let randomStr = '';
  for (let i = 0; i < 16; i++) {
    randomStr += CROCKFORD[(random[i] ?? 0) % 32];
  }
  return timeChars.join('') + randomStr;
}
