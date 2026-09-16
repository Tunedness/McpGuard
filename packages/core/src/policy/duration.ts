/**
 * Durations, as a person writes them.
 *
 * `10m` is read far more reliably than `600000` at the top of an incident, and
 * the schema accepts a plain number of milliseconds as well so a generated
 * policy does not have to format one.
 */

/** The accepted shape, as a source string so the JSON Schema can carry it too. */
export const DURATION_PATTERN = '^\\d+(ms|s|m|h|d)$';

/** What the user is told when the shape is wrong. */
export const DURATION_MESSAGE =
  'expected a duration like `500ms`, `30s`, `10m`, `2h`, `1d`, or a number of milliseconds';

const UNITS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/**
 * Parses a duration to milliseconds.
 *
 * A plain number is already milliseconds and passes through. The regex has
 * matched before this runs, so the failure branch is unreachable from the
 * schema — it exists because this function is exported and someone will
 * eventually call it directly.
 */
export function parseDuration(value: string | number): number {
  if (typeof value === 'number') return value;
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(value);
  if (match === null) throw new Error(`${DURATION_MESSAGE}; got \`${value}\``);
  const [, digits, unit] = match;
  return Number(digits) * (UNITS[unit as string] ?? 1);
}
