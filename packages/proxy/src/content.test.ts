import { describe, expect, it } from 'vitest';
import { extractText, type ResultLike, replaceText } from './content.js';

/**
 * Pulling text out of an MCP result and putting the guarded text back, without
 * disturbing anything the proxy does not understand.
 */

describe('extractText', () => {
  it('pulls text blocks out of a CallToolResult', () => {
    const result: ResultLike = {
      content: [
        { type: 'text', text: 'first' },
        { type: 'image', data: 'xxx' },
        { type: 'text', text: 'second' },
      ],
    };
    expect(extractText(result).map((r) => r.text)).toEqual(['first', 'second']);
  });

  it('pulls text out of a ReadResourceResult contents array', () => {
    const result: ResultLike = { contents: [{ type: 'text', text: 'body' }] };
    expect(extractText(result).map((r) => r.text)).toEqual(['body']);
  });

  it('returns nothing for a result with no text blocks', () => {
    expect(extractText({ content: [{ type: 'image', data: 'x' }] })).toEqual([]);
  });
});

describe('replaceText', () => {
  it('replaces only the named blocks and carries everything else through', () => {
    const result: ResultLike = {
      isError: false,
      content: [
        { type: 'text', text: 'raw one', annotations: { audience: ['user'] } },
        { type: 'image', data: 'xxx' },
      ],
    };
    const guarded = new Map([['0', 'masked one']]);
    const out = replaceText(result, guarded);
    const blocks = out.content as { type: string; text?: string; annotations?: unknown }[];

    expect(blocks[0]?.text).toBe('masked one');
    // The block's other fields and the sibling image block are untouched.
    expect(blocks[0]?.annotations).toEqual({ audience: ['user'] });
    expect(blocks[1]).toEqual({ type: 'image', data: 'xxx' });
    expect(out.isError).toBe(false);
  });

  it('leaves a result with no content array alone', () => {
    const result: ResultLike = { structuredContent: { x: 1 } };
    expect(replaceText(result, new Map())).toEqual(result);
  });
});
