/**
 * Deterministic JSON.
 *
 * `JSON.stringify` is not usable for fingerprinting: it emits object keys in
 * insertion order, except that integer-like keys are hoisted and sorted
 * numerically. Two logically identical payloads can therefore serialise
 * differently — and in this package a serialisation difference is a manifest
 * that looks tampered with, or an audit chain that will not verify.
 */

/** Any value that survives a JSON round trip. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

function writeString(value: string): string {
  return JSON.stringify(value);
}

function writeNumber(value: number): string {
  // NaN and ±Infinity have no JSON representation; collapsing them to null
  // matches `JSON.stringify` and keeps fingerprints stable.
  return Number.isFinite(value) ? String(value) : 'null';
}

/**
 * Serialises a JSON value with object keys sorted lexicographically.
 *
 * Array order is preserved — the order of a list is semantic. A server that
 * returns its tools in a different order has not changed its tools, but a
 * server that renamed one has, and sorting arrays would hide the difference
 * between those two cases.
 */
export function stableStringify(value: JsonValue): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return writeString(value);
    case 'number':
      return writeNumber(value);
    case 'boolean':
      return value ? 'true' : 'false';
    default:
      break;
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const entry = value[key];
    if (entry === undefined) continue;
    parts.push(`${writeString(key)}:${stableStringify(entry)}`);
  }
  return `{${parts.join(',')}}`;
}

/**
 * Coerces an arbitrary value into a {@link JsonValue}, the way `JSON.stringify`
 * would: `undefined` and functions vanish from objects and become `null` in
 * arrays, `bigint` becomes its decimal string, and anything exotic becomes
 * `null`.
 *
 * Tool results arrive from a server that is not trusted to be well-behaved, so
 * every value that reaches {@link stableStringify} goes through here first.
 */
export function toJsonValue(value: unknown): JsonValue {
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value;
    case 'number':
      return Number.isFinite(value) ? value : null;
    case 'bigint':
      return value.toString();
    case 'undefined':
    case 'function':
    case 'symbol':
      return null;
    default:
      break;
  }
  if (value === null) return null;
  if (Array.isArray(value)) return value.map(toJsonValue);
  const out: { [k: string]: JsonValue } = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (entry === undefined || typeof entry === 'function' || typeof entry === 'symbol') continue;
    out[key] = toJsonValue(entry);
  }
  return out;
}
