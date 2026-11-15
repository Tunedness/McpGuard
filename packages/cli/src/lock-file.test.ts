import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emptyLock, lockServer, serializeLock, withServerLock } from '@tunedness/mcpguard-core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resolveAgainst } from './config.js';
import { fileLockStore } from './lock-file.js';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcpguard-lockfile-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('resolveAgainst', () => {
  it('resolves a relative path against the policy directory and leaves an absolute one', () => {
    expect(resolveAgainst('/etc/app', 'guardlock.json')).toBe('/etc/app/guardlock.json');
    expect(resolveAgainst('/etc/app', '.mcpguard/audit.jsonl')).toBe(
      '/etc/app/.mcpguard/audit.jsonl',
    );
    expect(resolveAgainst('/etc/app', '/srv/lock.json')).toBe('/srv/lock.json');
  });
});

describe('fileLockStore', () => {
  const lock = withServerLock(emptyLock(), 's', lockServer([{ name: 't', description: 'd' }]));

  it('says absent for a file that is not there', () => {
    expect(fileLockStore(join(dir, 'guardlock.json')).read()).toEqual({ kind: 'absent' });
  });

  it('says invalid, with a reason, for a file that cannot be trusted', () => {
    const path = join(dir, 'guardlock.json');
    writeFileSync(path, '{"version": 2}');
    const state = fileLockStore(path).read();

    expect(state.kind).toBe('invalid');
  });

  it('says invalid for a path that is a directory, not absent', () => {
    expect(fileLockStore(dir).read().kind).toBe('invalid');
  });

  it('writes the serialised lock, creating the directory, and leaves no temporary file', () => {
    const path = join(dir, 'nested', 'guardlock.json');
    const store = fileLockStore(path);
    store.write(lock);

    expect(readFileSync(path, 'utf8')).toBe(serializeLock(lock));
    expect(store.read()).toEqual({ kind: 'ok', lock });
    expect(readdirSync(join(dir, 'nested'))).toEqual(['guardlock.json']);
  });

  it('replaces an existing lock whole', () => {
    const path = join(dir, 'guardlock.json');
    const store = fileLockStore(path);
    store.write(lock);
    store.write(emptyLock());

    expect(readFileSync(path, 'utf8')).toBe(serializeLock(emptyLock()));
  });

  it('cleans up and rethrows when the write fails', () => {
    // A directory where the file should go makes the rename fail.
    writeFileSync(join(dir, 'blocker'), '');
    const store = fileLockStore(join(dir, 'blocker', 'guardlock.json'));

    expect(() => store.write(lock)).toThrow();
    expect(readdirSync(dir).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });
});
