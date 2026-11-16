/**
 * The ruleset schema.
 *
 * The ruleset is data, loaded at runtime, and a badly-formed pattern is a
 * self-inflicted denial of service. Most of the safety is structural: the
 * pattern kinds are ordered by how many rules should use each, and the two
 * cheap kinds cannot express catastrophic backtracking at all.
 */
import { z } from 'zod';
import { HEALTH_KINDS } from '../pii/kinds.js';

export const RuleId = z
  .string()
  .max(64)
  .regex(/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/);

/**
 * How a rule matches. In descending order of how many rules should use it:
 *
 * - `literal` — a folded substring, found by the shared automaton. No
 *   backtracking, O(n) however many rules there are. Most rules live here.
 * - `phrase` — an ordered token sequence with a bounded gap, so
 *   `["ignore","previous","instruction"]` matches without a regex, and
 *   `tokenMatch: "prefix"` lets `talimat` match `talimatlarınızı` — which is
 *   what makes a Turkish ruleset maintainable rather than a suffix enumeration.
 * - `regex` — allowed, restricted, and never run over the whole document (only
 *   the segment its prefilter hit). Unbounded quantifiers are rejected at load.
 */
export const PatternSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('literal'),
    value: z.string().min(3).max(200),
    fold: z.enum(['case', 'skeleton']).default('skeleton'),
  }),
  z.strictObject({
    kind: z.literal('phrase'),
    tokens: z.array(z.string().min(2).max(40)).min(2).max(6),
    maxGap: z.number().int().min(0).max(8).default(3),
    tokenMatch: z.enum(['exact', 'prefix']).default('exact'),
    fold: z.enum(['case', 'skeleton']).default('skeleton'),
  }),
  z.strictObject({
    kind: z.literal('regex'),
    source: z.string().min(3).max(200),
    flags: z
      .string()
      .regex(/^[imsu]*$/)
      .default('iu'),
    /** A required literal ≥ 3 chars that gates the regex. Derived if omitted. */
    prefilter: z.string().min(3).max(40).optional(),
  }),
]);

export const RuleSchema = z.strictObject({
  id: RuleId,
  category: z.enum([
    'instruction-override',
    'role-switch',
    'exfiltration',
    'tool-abuse',
    'secret-request',
    'persistence',
    'obfuscation',
    'jailbreak',
    'data-poisoning',
  ]),
  family: z.enum(['signature', 'frame', 'exfil', 'anomaly']),
  pattern: PatternSchema,
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  /** Fixed-point, 0–1000. Never a float (ADR-009). */
  weight: z.number().int().min(0).max(1000),
  locale: z.enum(['und', 'en', 'tr']).default('und'),
  contentKinds: z
    .array(z.enum(['tool_result', 'resource', 'tool_description', 'prompt']))
    .default(['tool_result', 'resource']),
  /** Whether the rule may carry a verdict with no second family behind it. */
  standalone: z.boolean().default(false),
  /** Damping when the hit sits in quoted code, on the 0–1000 scale. */
  quotedDamping: z.number().int().min(0).max(1000).default(400),
  description: z.string().min(10).max(300),
  /** Every rule ships the strings that must and must not match it. */
  testVectors: z.strictObject({
    match: z.array(z.string()).min(1).max(10),
    noMatch: z.array(z.string()).min(1).max(10),
  }),
});

/**
 * Lexicons the structural detectors read.
 *
 * These are data for the same reason the rules are: the imperative detector is
 * a closed-lexicon classifier, not an NLP model, and which verbs count as
 * agent-capability verbs is a list that evolves with the attacks — so it ships
 * versioned alongside the rules rather than baked into the engine.
 */
export const LexiconSchema = z.strictObject({
  /** English agent-capability verbs, matched verb-initial. */
  verbsEn: z.array(z.string().min(2)).default([]),
  /** Turkish action stems, matched against a clause's final token. */
  verbsTr: z.array(z.string().min(2)).default([]),
  /** Imperative phrases that are ordinary help, not injection. */
  benignImperatives: z.array(z.string().min(2)).default([]),
});

/**
 * A keyword for a PII recogniser: a literal word or phrase, never a pattern.
 *
 * It is tokenised on letters and digits and compared as text, so there is no
 * syntax in it to get wrong and nothing to backtrack. The one rule is that it
 * has a letter or a digit to match on.
 */
const PiiWord = z
  .string()
  .max(60)
  .regex(/[\p{L}\p{N}]/u);
const PiiWords = z.array(PiiWord).min(1).max(200);

/**
 * The PII section: keyword context and profile membership, as data (ADR-012).
 *
 * The candidate shapes and validators stay in code. Digested on its own as
 * `piiDigest`, so the ruleset's `digest` — and every injection result keyed on
 * it — does not move when a keyword does.
 */
export const PiiDataSchema = z.strictObject({
  /** Which recognisers each profile switches on. */
  profiles: z.strictObject({ health: z.array(z.enum(HEALTH_KINDS)).min(1) }),
  /** Words that must come before a reference number. */
  anchors: z.strictObject({ health_ref: PiiWords }),
  /** Words that must sit beside a value for it to count. */
  context: z.strictObject({
    health_date: PiiWords,
    ssn_us: PiiWords,
    icd10: PiiWords,
    gs1_serial: PiiWords,
  }),
  /** Words that say a keyword hit is not clinical; a candidate beside one is not masked. */
  exclude: z.strictObject({ health_ref: PiiWords, health_date: PiiWords }),
  /**
   * Words that make an anchor or context phrase unambiguously clinical. A phrase
   * that contains one is never suppressed by an exclusion word; one that does
   * not (`takip no`, `admission`) is.
   */
  strong: z.strictObject({ health_ref: PiiWords, health_date: PiiWords }),
  /** Words a profile adds to a base recogniser's own context. */
  profileContext: z.strictObject({ tckn: PiiWords, phone: PiiWords }),
});

export const RulesetSchema = z.strictObject({
  schemaVersion: z.literal(1),
  rulesetVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
  /** Semver range of `@tunedness/mcpguard-detect` this ruleset targets. */
  engineRange: z.string().min(1),
  locales: z.array(z.enum(['und', 'en', 'tr'])).min(1),
  rules: z.array(RuleSchema).min(1).max(5000),
  lexicons: LexiconSchema.prefault({}),
  /** Optional: a ruleset without it cannot serve `pii.profile: health`. */
  pii: PiiDataSchema.optional(),
});

export type Rule = z.infer<typeof RuleSchema>;
export type PiiDataSection = z.infer<typeof PiiDataSchema>;
export type Lexicons = z.infer<typeof LexiconSchema>;
export type RulesetData = z.infer<typeof RulesetSchema>;
export type Pattern = z.infer<typeof PatternSchema>;
