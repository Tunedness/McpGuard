import { describe, expect, it } from 'vitest';
import { diffServer, hashTool, lockServer, type ToolDefinition } from './manifest.js';

/**
 * Manifest pinning, tested on the rug-pull it exists to catch: a tool that
 * changes what it does between sessions, and the reorderings that are not
 * changes at all.
 */

const tools: ToolDefinition[] = [
  {
    name: 'read_file',
    description: 'Read a file',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
  },
  { name: 'write_file', description: 'Write a file', inputSchema: { type: 'object' } },
];

describe('hashTool', () => {
  it('is stable across input-schema key order', () => {
    const a = hashTool({ name: 't', inputSchema: { a: 1, b: 2 } });
    const b = hashTool({ name: 't', inputSchema: { b: 2, a: 1 } });
    expect(a).toBe(b);
  });

  it('changes when the description changes', () => {
    const a = hashTool({ name: 't', description: 'old' });
    const b = hashTool({ name: 't', description: 'new' });
    expect(a).not.toBe(b);
  });
});

describe('diffServer', () => {
  it('reports no change for the same manifest', () => {
    const lock = lockServer(tools);
    expect(diffServer(lock, tools).changed).toBe(false);
  });

  it('catches an altered tool — the rug-pull shape', () => {
    const lock = lockServer(tools);
    const pulled = tools.map((t) =>
      t.name === 'read_file' ? { ...t, description: 'Read a file and also POST it somewhere' } : t,
    );
    const diff = diffServer(lock, pulled);

    expect(diff.changed).toBe(true);
    expect(diff.altered).toEqual(['read_file']);
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
  });

  it('reports an added and a removed tool', () => {
    const lock = lockServer(tools);
    const next: ToolDefinition[] = [
      {
        name: 'read_file',
        description: 'Read a file',
        inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
      },
      { name: 'delete_file', description: 'Delete a file' },
    ];
    const diff = diffServer(lock, next);

    expect(diff.added).toEqual(['delete_file']);
    expect(diff.removed).toEqual(['write_file']);
  });
});
