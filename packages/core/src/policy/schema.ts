/**
 * `guardpolicy.v1` — the whole configuration surface, as one zod object.
 *
 * Two rules hold this file together.
 *
 * **Defaults live here and nowhere else.** The CLI never supplies a fallback of
 * its own, so `{ version: 1 }` parses into a complete, safe policy and there is
 * exactly one place to read to find out what a field does when it is absent.
 *
 * **Every object is `z.strictObject`.** A misspelled key is a security control
 * that silently did not apply; failing at load time is the only acceptable
 * behaviour for a tool whose job is to be in the way.
 *
 * The committed JSON Schema in `schemas/` is generated from this object, never
 * written by hand, and `schema:check` fails CI when the two disagree — an
 * editor that validates a policy the runtime then rejects is worse than no
 * editor support at all.
 */
import { z } from 'zod';
import { DURATION_MESSAGE, DURATION_PATTERN, parseDuration } from './duration.js';

const durationInput = z.union(
  [
    z.string().regex(new RegExp(DURATION_PATTERN), DURATION_MESSAGE),
    z.number().int().nonnegative(),
  ],
  { error: DURATION_MESSAGE },
);

/** A duration field with a default, parsed to milliseconds. */
const duration = (fallback: string | number) =>
  durationInput.prefault(fallback).transform(parseDuration);

const positiveInt = () => z.number().int().positive();

/** A score on the 0–100 scale every verdict speaks in. Integer by ADR-009. */
const score = () => z.number().int().min(0).max(100);

const glob = () => z.string().min(1).max(200);

// ---------------------------------------------------------------------------
// access control
// ---------------------------------------------------------------------------

const ToolRuleSchema = z.strictObject({
  /** Glob over `<server>__<tool>`. First match wins. */
  match: glob(),
  action: z.enum(['allow', 'deny']).default('allow'),
  /** Roles this rule applies to. Empty means every caller. */
  roles: z.array(z.string().min(1)).default([]),
  /** Shown to the agent when the call is refused, and written to the audit log. */
  note: z.string().min(1).max(300).optional(),
});

/**
 * A combination of capabilities that is dangerous only together.
 *
 * "Read a file" is fine. "Reach an arbitrary host" is fine. A session that does
 * both is the exfiltration shape the product exists to catch, and no per-tool
 * rule can express it because each tool is individually reasonable.
 */
const CombinationRuleSchema = z.strictObject({
  id: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/),
  /** Every glob that must have matched, within the window, for the rule to fire. */
  all_of: z.array(glob()).min(2).max(8),
  action: z.enum(['deny', 'flag']).default('flag'),
  /** How far back the combination is looked for. */
  window: duration('10m'),
  note: z.string().min(1).max(300),
});

// ---------------------------------------------------------------------------
// scanning
// ---------------------------------------------------------------------------

/**
 * The scan fields, undefaulted, defined once.
 *
 * Two schemas are built from them: the settings block, where every field has a
 * default, and the per-tool override, where none does. They cannot be derived
 * from one another with `.partial()`, and that is worth writing down because
 * the attempt looks like it works: `.partial()` makes a key optional but leaves
 * the field's own `.default()` in place, so an override that mentions only
 * `action` parses into a *complete* settings object carrying the schema's
 * defaults for everything else. Laying that over the operator's `scan.default`
 * then silently discards it — `flag_at: 50` becomes 40 with nothing said.
 */
const scanField = {
  action: z.enum(['flag', 'strip', 'block']),
  flag_at: score(),
  block_at: score(),
  max_bytes: positiveInt(),
  on_degraded: z.enum(['flag', 'block', 'allow']),
} as const;

const ScanSettingsSchema = z.strictObject({
  /**
   * What to do when a scanned item lands at or above {@link flag_at}.
   *
   * `flag` is the default because PRD §8 lists false positives as the first
   * risk: content passes through byte-identical, the event is recorded, and an
   * operator can measure what enforcement would have done to their own traffic
   * before switching it on.
   */
  action: scanField.action.default('flag'),
  flag_at: scanField.flag_at.default(40),
  block_at: scanField.block_at.default(70),
  /**
   * Bytes of one content item that get full rule evaluation.
   *
   * Above this the item is scanned at its head, its tail and a fixed set of
   * interior windows, and marked `degraded` — never silently passed. The tail
   * is not optional: appending instructions after a large clean payload is an
   * attack family, not a hypothetical.
   */
  max_bytes: scanField.max_bytes.default(262_144),
  /** What a `degraded` (partially scanned) item is treated as. */
  on_degraded: scanField.on_degraded.default('flag'),
});

/** The same fields with no defaults at all, so an absent key stays absent. */
const ScanOverrideSchema = z.strictObject({
  action: scanField.action.optional(),
  flag_at: scanField.flag_at.optional(),
  block_at: scanField.block_at.optional(),
  max_bytes: scanField.max_bytes.optional(),
  on_degraded: scanField.on_degraded.optional(),
});

const ScanSchema = z
  .strictObject({
    default: ScanSettingsSchema.prefault({}),
    /** Per-tool overrides, keyed by `<server>__<tool>` glob. */
    tools: z.record(glob(), ScanOverrideSchema).default({}),
    /**
     * Per-rule weight overrides.
     *
     * Disabling a rule requires a `reason`, which is written to the audit log.
     * A `critical` rule cannot be zeroed here at all — only a ruleset release
     * can remove one. An operator must not be able to blind the proxy quietly.
     */
    rules: z
      .record(
        z.string().min(1).max(64),
        z.strictObject({
          weight: z.number().int().min(0).max(1000),
          reason: z.string().min(10).max(300),
        }),
      )
      .default({}),
  })
  .prefault({});

// ---------------------------------------------------------------------------
// PII
// ---------------------------------------------------------------------------

const PiiSchema = z
  .strictObject({
    enabled: z.boolean().default(true),
    /** Recogniser ids from the ruleset package. Empty means every shipped one. */
    recognizers: z.array(z.string().min(1)).default([]),
    /**
     * Whether a recogniser with a checksum requires it to pass.
     *
     * `true` is the default and the reason is arithmetic: eleven-digit numbers
     * are everywhere — order ids, invoice numbers, truncated timestamps — and
     * the check digits shrink the accidental-match space by about a hundredfold.
     * `false` is the regulated-tenant setting: a mistyped national ID is still
     * personal data, so a checksum failure still masks when a context keyword
     * sits beside it. The benchmark reports both operating points rather than
     * choosing one silently.
     */
    strict_checksum: z.boolean().default(true),
    /** Digits left visible for reconciliation. Zero means a full mask. */
    keep_last: z.number().int().min(0).max(4).default(0),
    /**
     * Whether a masked value carries a short correlation tag.
     *
     * The tag is a truncated keyed hash, so an operator can see that the same
     * identity appears in four results without recovering it. It is short
     * enough to collide on purpose, which is what stops it becoming a lookup
     * key. Off by default: linkability is a trade the tenant opts into.
     */
    correlation_tags: z.boolean().default(false),
  })
  .prefault({});

// ---------------------------------------------------------------------------
// audit, lock, telemetry
// ---------------------------------------------------------------------------

const AuditSchema = z
  .strictObject({
    enabled: z.boolean().default(true),
    /** Relative paths resolve against the policy file, not the process cwd. */
    path: z.string().min(1).default('.mcpguard/audit.jsonl'),
    /** How often the running chain head is published outside the file. */
    checkpoint_every: positiveInt().default(100),
    /**
     * Where the checkpoint goes.
     *
     * Never stdout. In `wrap` mode stdout is the agent's JSON-RPC stream and a
     * single extra byte on it corrupts every frame after — with the blame
     * landing on the wrapped server. ADR-004's original text said
     * "stdout/syslog"; this is the amendment.
     */
    checkpoint_to: z.enum(['stderr', 'syslog', 'none']).default('stderr'),
    /**
     * Environment variable holding the key that fingerprints raw content.
     *
     * Absent means no raw-content fingerprint is recorded at all. That is a
     * weaker audit trail, and it is still better than a plain digest of
     * low-entropy content, which is a recovery path wearing a hash's clothes.
     */
    key_env: z.string().min(1).optional(),
  })
  .prefault({});

const LockSchema = z
  .strictObject({
    enabled: z.boolean().default(true),
    path: z.string().min(1).default('guardlock.json'),
    /**
     * What happens the first time a server is seen.
     *
     * `write` is trust-on-first-use: record what the server says and hold it to
     * that afterwards. `require` refuses to run without an existing entry,
     * which is the setting for a deployment where the lock file is reviewed and
     * shipped rather than discovered.
     */
    on_first_use: z.enum(['write', 'require']).default('write'),
    on_mismatch: z.enum(['halt', 'flag']).default('halt'),
  })
  .prefault({});

const TelemetrySchema = z
  .strictObject({
    /** Off by default. McpGuard is fully functional with no collector at all. */
    enabled: z.boolean().default(false),
    endpoint: z.url().optional(),
    service_name: z.string().min(1).default('mcpguard'),
    headers_env: z.string().min(1).optional(),
  })
  .prefault({});

const SessionSchema = z
  .strictObject({
    /**
     * How an HTTP request is attributed to a session.
     *
     * `auto` walks the ladder in ADR-006. In `wrap` mode this field is not read
     * at all: one child process is one connection is one session, exactly, with
     * nothing to configure.
     */
    key: z.string().min(1).default('auto'),
    idle_timeout: duration('10m'),
  })
  .prefault({});

// ---------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------

export const GuardPolicySchemaV1 = z
  .strictObject({
    version: z.literal(1),
    /**
     * The global posture.
     *
     * `flag` computes every decision and forwards everything anyway, so the
     * false-positive rate can be measured on real traffic before enforcement is
     * switched on. `enforce` lets `deny`, `block` and `strip` actually happen.
     */
    mode: z.enum(['flag', 'enforce']).default('flag'),
    /** Upstream servers, keyed by the name that prefixes their tools. */
    servers: z
      .record(
        z.string().min(1).max(64),
        z.strictObject({
          /** Free-text, for reports. The transport is a CLI argument, not policy. */
          description: z.string().min(1).max(300).optional(),
          roles: z.array(z.string().min(1)).default([]),
        }),
      )
      .default({}),
    /** First match wins. An unmatched tool is allowed. */
    tools: z.array(ToolRuleSchema).prefault([{ match: '*', action: 'allow' }]),
    /** Caller identity → roles. An unlisted caller gets `roles: []`. */
    roles: z.record(z.string().min(1), z.array(z.string().min(1))).default({}),
    combinations: z.array(CombinationRuleSchema).default([]),
    scan: ScanSchema,
    pii: PiiSchema,
    audit: AuditSchema,
    lock: LockSchema,
    session: SessionSchema,
    telemetry: TelemetrySchema,
  })
  .meta({
    // No `id` here on purpose: registering one makes `z.toJSONSchema` hoist the
    // whole document into `$defs` behind a `$ref`, which every editor handles
    // and no human enjoys reading.
    title: 'GuardPolicy v1',
    description:
      'Security policy for McpGuard. Every field is optional except `version`; the defaults are safe (mode: flag, nothing blocked, nothing rewritten).',
  });

/** A fully defaulted, validated policy. Durations are milliseconds. */
export type GuardPolicy = z.infer<typeof GuardPolicySchemaV1>;
export type ToolRule = GuardPolicy['tools'][number];
export type CombinationRule = GuardPolicy['combinations'][number];
export type ScanSettings = GuardPolicy['scan']['default'];
/** A per-tool override: the same fields, every one of them optional. */
export type ScanSettingsOverride = GuardPolicy['scan']['tools'][string];
export type PolicyMode = GuardPolicy['mode'];
export type RuleAction = ToolRule['action'];
export type ScanAction = ScanSettings['action'];
