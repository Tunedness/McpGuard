import { describe, expect, it } from 'vitest';
import { stableStringify, toJsonValue } from './json.js';

/**
 * The serialiser two load-bearing things are built on: the manifest hash that
 * detects a rug-pull, and the audit chain that detects tampering. A difference
 * here is a false alarm in the first case and a missed one in the second.
 */

describe('stableStringify', () => {
  it('sorts object keys, so insertion order cannot change a digest', () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe(stableStringify({ a: 2, b: 1 }));
  });

  it('sorts nested keys too', () => {
    expect(stableStringify({ x: { d: 1, c: 2 } })).toBe('{"x":{"c":2,"d":1}}');
  });

  it('keeps integer-like keys where sorting puts them, not where JSON.stringify does', () => {
    // `JSON.stringify` hoists integer-like keys and sorts them numerically.
    // That is the exact behaviour this function exists to not have.
    expect(stableStringify({ '10': 'a', '2': 'b', z: 'c' })).toBe('{"10":"a","2":"b","z":"c"}');
  });

  it('preserves array order, because the order of a list is semantic', () => {
    // A server returning its tools in a new order has not changed its tools;
    // one that renamed a tool has. Sorting arrays would fuse those two cases.
    expect(stableStringify(['b', 'a'])).toBe('["b","a"]');
  });

  it('renders the primitives the way JSON does', () => {
    expect(stableStringify(null)).toBe('null');
    expect(stableStringify(true)).toBe('true');
    expect(stableStringify(false)).toBe('false');
    expect(stableStringify('a"b')).toBe('"a\\"b"');
    expect(stableStringify(1.5)).toBe('1.5');
  });

  it('collapses non-finite numbers to null, as JSON.stringify does', () => {
    expect(stableStringify(Number.NaN)).toBe('null');
    expect(stableStringify(Number.POSITIVE_INFINITY)).toBe('null');
  });

  it('skips keys whose value is undefined', () => {
    expect(stableStringify({ a: 1, b: undefined } as never)).toBe('{"a":1}');
  });
});

describe('toJsonValue', () => {
  it('passes strings, booleans and finite numbers through', () => {
    expect(toJsonValue('x')).toBe('x');
    expect(toJsonValue(true)).toBe(true);
    expect(toJsonValue(3)).toBe(3);
  });

  it('turns a bigint into its decimal string rather than throwing', () => {
    // A tool result comes from a server nobody vetted. Throwing here would turn
    // an odd payload into an outage.
    expect(toJsonValue(10n)).toBe('10');
  });

  it('nulls out the things JSON has no room for', () => {
    expect(toJsonValue(undefined)).toBeNull();
    expect(toJsonValue(() => 0)).toBeNull();
    expect(toJsonValue(Symbol('s'))).toBeNull();
    expect(toJsonValue(Number.NaN)).toBeNull();
    expect(toJsonValue(null)).toBeNull();
  });

  it('drops functions and symbols from objects but nulls them inside arrays', () => {
    expect(toJsonValue({ a: 1, f: () => 0 })).toEqual({ a: 1 });
    expect(toJsonValue([1, () => 0])).toEqual([1, null]);
  });

  it('recurses through arrays and objects', () => {
    expect(toJsonValue({ a: [{ b: 1n }] })).toEqual({ a: [{ b: '1' }] });
  });
});
