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

/**
 * The recogniser ids a policy may name.
 *
 * Duplicated from `@tunedness/mcpguard-detect` on purpose — this package does
 * not depend on the engine — and pinned to it by a test in the CLI. An unknown
 * id is a load error: it used to be skipped silently, and a typo in a
 * regulated tenant's list would have turned a recogniser off without a word.
 */
export const PII_RECOGNIZER_IDS = [
  'tckn',
  'vkn',
  'iban',
  'card',
  'phone',
  'email',
  'health_ref',
  'health_date',
  'gs1_serial',
  'ssn_us',
  'mbi_us',
  'icd10',
  'atc',
] as const;

const PiiSchema = z
  .strictObject({
    enabled: z.boolean().default(true),
    /**
     * Which recognisers run. `default` is the six shipped ones, unchanged.
     * `health` adds the health identifiers (`health_ref`, `health_date`,
     * `gs1_serial`, `ssn_us`, `mbi_us`) and the profile's extra keywords for the
     * national id and phone recognisers. It never turns on `icd10` or `atc`:
     * those reveal a diagnosis or a drug class, and masking the diagnosis can
     * break the very workflow a clinical agent exists for, so they are named
     * in `recognizers` or not run.
     */
    profile: z.enum(['default', 'health']).default('default'),
    /**
     * Recogniser ids to run. Empty means the base set plus what `profile`
     * switches on. A non-empty list is the complete list: the profile adds no
     * recogniser to it, though its extra keywords for `tckn` and `phone` still
     * apply when those are in it. An id that does not exist is an error.
     */
    recognizers: z.array(z.enum(PII_RECOGNIZER_IDS)).default([]),
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
    /**
     * Environment variable holding the key that correlation tags are keyed with.
     *
     * Required when `correlation_tags` is on: a tag without a key is either no
     * tag or an unkeyed one, and an unkeyed truncated hash is exactly the lookup
     * key the tag is built not to be. The key itself never sits in the policy.
     */
    correlation_key_env: z.string().min(1).optional(),
  })
  .prefault({});

// ---------------------------------------------------------------------------
// audit, lock, telemetry
// ---------------------------------------------------------------------------

/**
 * Where syslog checkpoints go, and there is no default: `udp://host[:port]`
 * (RFC 5426), `tcp://host[:port]` (RFC 6587, one message per line) or
 * `unix:///absolute/path` (a stream socket; `/dev/log` is a datagram socket Node
 * cannot write to). The port defaults to 514.
 *
 * UDP gives no delivery guarantee: with nothing listening the checkpoint can be
 * lost, and only a local error (a refused loopback port, a failed send) is
 * reported. An audit trail that must arrive wants `tcp://` or `unix://`. The CLI
 * parses the same grammar into an address; this is the check that stops a bad
 * one at `validate`.
 */
const SYSLOG_TARGET =
  /^(?:(?:udp|tcp):\/\/(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?|unix:\/\/\/[^\s\0]+)$/;

/** What the error says when the target is missing or wrong: the three forms, as examples. */
const SYSLOG_TARGET_FORMS =
  'udp://127.0.0.1:514, tcp://logs.example.com:514 or unix:///run/mcpguard/syslog.sock';

/** The RFC 5424 facilities a checkpoint may be filed under. */
const SYSLOG_FACILITIES = [
  'daemon',
  'auth',
  'authpriv',
  'user',
  'local0',
  'local1',
  'local2',
  'local3',
  'local4',
  'local5',
  'local6',
  'local7',
] as const;

const SyslogSchema = z
  .strictObject({
    /** Required when `audit.checkpoint_to` is `syslog`, and checked there; ignored otherwise. */
    target: z.string().regex(SYSLOG_TARGET, `must be one of ${SYSLOG_TARGET_FORMS}`).optional(),
    /** Security records belong under `authpriv`, which most syslogds route to a restricted file. */
    facility: z.enum(SYSLOG_FACILITIES).default('authpriv'),
  })
  .superRefine((syslog, ctx) => {
    const port = /^(?:udp|tcp):\/\/.*:([0-9]+)$/.exec(syslog.target ?? '')?.[1];
    if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) {
      ctx.addIssue({ code: 'custom', path: ['target'], message: 'the port must be 1-65535' });
    }
  })
  .prefault({});

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
     * Where `checkpoint_to: syslog` writes. A failure never stops a call; it is
     * reported on stderr and as a `security_event`. UDP cannot know whether anyone
     * received the line, so use `tcp://` or `unix://` when the checkpoint must arrive.
     */
    syslog: SyslogSchema,
    /**
     * Environment variable holding the key that fingerprints raw content.
     *
     * Absent means no raw-content fingerprint is recorded at all. That is a
     * weaker audit trail, and it is still better than a plain digest of
     * low-entropy content, which is a recovery path wearing a hash's clothes.
     */
    key_env: z.string().min(1).optional(),
  })
  .superRefine((audit, ctx) => {
    if (audit.checkpoint_to === 'syslog' && audit.syslog.target === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['syslog', 'target'],
        message: `audit.checkpoint_to is syslog, so audit.syslog.target is required: ${SYSLOG_TARGET_FORMS}`,
      });
    }
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

/** Whether a URL's host is this machine, by name or address. */
function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

/**
 * The tier-2 judge (ADR-012): off, and local, unless the operator says otherwise.
 *
 * The judge reads masked content, but "masked" is the policy's word and a
 * security tool does not talk to the network on its own say-so. So the endpoint
 * must be this machine unless `allow_remote` is set, and a remote one must be
 * https. The defaults for `timeout`, `max_inflight` and the breaker are one
 * measurement on one setup (Faz 22): gemma4:12b Q4_K_M through Ollama on the
 * author's machine, one request at a time, 124 calls: p50 2.7 s, p95 3.3 s, p99
 * 3.6 s. A
 * faster server can shorten them. How many calls can run at once is the model
 * server's own limit, not McpGuard's: Ollama serves one request at a time by
 * default and queues the rest, so `max_inflight` above that only queues.
 */
const JudgeSchema = z
  .strictObject({
    /** Off by default (ADR-003): the default install makes no model call and no connection. */
    enabled: z.boolean().default(false),
    /** The only adapter for now: an OpenAI-compatible `/v1/chat/completions` endpoint. */
    adapter: z.enum(['openai_chat']).default('openai_chat'),
    /** Required when enabled. Ollama, llama-server and vLLM all serve this shape. */
    endpoint: z.url({ protocol: /^https?$/ }).optional(),
    /** Required when enabled. McpGuard recommends no model; the operator picks one. */
    model: z.string().min(1).max(128).optional(),
    /** A revision or digest the operator pins; written to every record that used the judge. */
    model_revision: z.string().min(1).max(128).optional(),
    /**
     * How long one judge call may take before tier 1's decision stands. 5s covers
     * the measured p99 (3.9s) of a 12B model on a laptop with room to spare; a
     * faster server can set it far lower.
     */
    timeout: duration('5000ms'),
    /**
     * Where the judged band starts. Absent, each tool's own `flag_at`. Lowering it
     * sends lower-scoring items to the judge, at the price of more model calls.
     */
    band_from: score().optional(),
    /**
     * Sent as `reasoning_effort`. A model that thinks first (Gemma 4, Qwen 3,
     * gpt-oss) spends its token budget on the thinking and answers nothing, so for a
     * judge the default is `none`; Ollama honours it. `omit` leaves the field out of
     * the request altogether, for a server that does not know it: one that rejects the
     * field answers every call with an error (recorded as `http_400`, say), and there
     * is no retry and no guess, so the way out is to set `omit` here.
     */
    reasoning_effort: z.enum(['none', 'minimal', 'low', 'medium', 'high', 'omit']).default('none'),
    /**
     * The most tokens the answer may use. The answer is one small JSON object, so the
     * default is tiny; a model whose thinking cannot be switched off needs far more.
     */
    max_tokens: z.number().int().min(16).max(8192).default(32),
    /**
     * Judge calls in flight at once. A call over the limit is skipped, never queued.
     * Keep it at or below what the model server runs at once: Ollama runs one and
     * queues the rest, so the queued calls only time out.
     */
    max_inflight: positiveInt().default(1),
    /** Bytes of one item shown to the judge; a longer one is sampled head and tail. */
    max_input_bytes: positiveInt().default(16_384),
    /** Consecutive timeouts or errors that open the circuit breaker. */
    circuit_failures: positiveInt().default(5),
    /** How long an open breaker keeps the judge off before one trial call. */
    circuit_open_for: duration('30s'),
    /** Permits an endpoint that is not this machine. Then the endpoint must be https. */
    allow_remote: z.boolean().default(false),
    /**
     * Environment variable holding extra request headers as `Name=value,Name2=value2`
     * (an API key, for a remote judge). The value never sits in the policy or a record.
     */
    headers_env: z.string().min(1).optional(),
  })
  .superRefine((judge, ctx) => {
    if (judge.timeout < 1) {
      ctx.addIssue({ code: 'custom', path: ['timeout'], message: 'must be at least 1ms' });
    }
    if (!judge.enabled) return;
    if (judge.endpoint === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['endpoint'],
        message: 'judge.enabled is true, so judge.endpoint is required',
      });
    }
    if (judge.model === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['model'],
        message: 'judge.enabled is true, so judge.model is required',
      });
    }
    if (judge.endpoint === undefined) return;
    const url = new URL(judge.endpoint);
    if (url.username !== '' || url.password !== '') {
      ctx.addIssue({
        code: 'custom',
        path: ['endpoint'],
        message:
          'the endpoint must not carry credentials; put them in a header named by judge.headers_env',
      });
    }
    if (!isLoopbackHost(url.hostname)) {
      if (!judge.allow_remote) {
        ctx.addIssue({
          code: 'custom',
          path: ['endpoint'],
          message:
            'the judge endpoint is not on this machine (localhost, 127.0.0.1 or [::1]); set judge.allow_remote: true to send masked content to it',
        });
      } else if (url.protocol !== 'https:') {
        ctx.addIssue({
          code: 'custom',
          path: ['endpoint'],
          message: 'a remote judge endpoint must be https',
        });
      }
    }
  });

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
    /**
     * The most attribution entries the gateway keeps (ADR-011). An entry is one
     * guessed `clientInfo` + address binding; when the table is full the one
     * idle longest is dropped, so a caller cannot grow it without bound.
     */
    max_sessions: positiveInt().default(1024),
    /**
     * The most legacy upstream connections the gateway holds open at once, per
     * server (ADR-011). A legacy downstream session owns one upstream
     * connection — for a stdio server, one child process — so this is the real
     * ceiling. When it is reached a new `initialize` is answered `503`; an
     * existing session is never evicted to make room.
     */
    max_upstream_connections: positiveInt().default(32),
  })
  .prefault({});

/**
 * Where an upstream server is reached (ADR-011): a streamable HTTP endpoint, or
 * a command to spawn that speaks stdio. Which servers a gateway will talk to is
 * a security decision, so it is policy, not a flag.
 */
const UpstreamSchema = z.union([
  z.strictObject({ url: z.url({ protocol: /^https?$/ }) }),
  z.strictObject({
    command: z.string().min(1),
    args: z.array(z.string()).default([]),
  }),
]);

const HttpSchema = z
  .strictObject({
    /** The largest request body accepted; a bigger one is answered `413`. */
    max_body_bytes: positiveInt().default(4_194_304),
    /** The largest response read from a streamable HTTP upstream. */
    max_upstream_response_bytes: positiveInt().default(16_777_216),
    /** Requests being served at once; beyond it, `503` with `Retry-After`. */
    max_inflight: positiveInt().default(256),
    /**
     * `Host` values the gateway answers to, as hostnames. Empty means the
     * loopback names on a loopback bind; a non-loopback bind refuses to start
     * without them.
     */
    allowed_hosts: z.array(z.string().min(1)).default([]),
    /** `Origin` hostnames accepted beyond localhost. Empty means localhost only. */
    allowed_origins: z.array(z.string().min(1)).default([]),
  })
  .prefault({});

const AuthSchema = z
  .strictObject({
    /**
     * Static bearer tokens, by the SHA-256 of the token and never the token.
     * The identity a token maps to is exact (ADR-011): the operator wrote the
     * mapping. Several tokens may name one identity, which is how a token is
     * rotated without a gap.
     */
    tokens: z
      .array(
        z.strictObject({
          identity: z.string().min(1).max(128),
          token_sha256: z.string().regex(/^[0-9a-f]{64}$/, 'expected 64 lowercase hex digits'),
        }),
      )
      .default([])
      .refine(
        (tokens) => new Set(tokens.map((token) => token.token_sha256)).size === tokens.length,
        {
          error: 'the same token_sha256 appears twice',
        },
      ),
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
          /** Free-text, for reports. */
          description: z.string().min(1).max(300).optional(),
          /**
           * How `serve` reaches this server (ADR-011). `wrap` ignores it: there
           * the transport is the command after `--`.
           */
          upstream: UpstreamSchema.optional(),
          /**
           * Per-server PII masking, over the global `pii` block. Only the switch is
           * per server: what is recognised and how it is masked stay one decision
           * for the whole policy. Scan and access rules are per server already, by
           * the `<server>__<tool>` glob in `scan.tools` and `tools`.
           */
          pii: z.strictObject({ enabled: z.boolean() }).optional(),
          /**
           * Roles admitted to this server. When the list names any role, only a
           * caller holding one of them may send the server anything: `tools/list`,
           * `tools/call`, `resources/*`, `prompts/*` and every other request it
           * would be forwarded. A caller with no identity, or none of these roles,
           * gets a JSON-RPC error (`mode: enforce`) or is flagged and let through
           * (`mode: flag`). `initialize`, `ping` and `server/discover` belong to the
           * connection and are not covered. Empty or unset admits every caller. It
           * combines with `tools` rules, and the stricter of the two wins.
           */
          roles: z.array(z.string().min(1)).default([]).meta({
            description:
              'Roles admitted to this server. When non-empty, only a caller holding one of them may send the server any request: tools/list, tools/call, resources/*, prompts/* and every other request that would be forwarded. A caller with no identity or none of these roles gets a JSON-RPC error (enforce) or is flagged and let through (flag). initialize, ping and server/discover are connection-level and not covered. Empty or unset admits every caller. Combined with `tools` rules, the stricter wins.',
          }),
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
    http: HttpSchema,
    auth: AuthSchema,
    telemetry: TelemetrySchema,
    /** Tier 2: an opt-in local judge for what tier 1 could not settle (ADR-012). */
    judge: JudgeSchema.prefault({}),
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
