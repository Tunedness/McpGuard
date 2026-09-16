/**
 * `@mcpguard/detect` — the tier-1 detection engine.
 *
 * Deterministic by construction, and that word is load-bearing here rather than
 * decorative: the score path is integer arithmetic, the ruleset is data with a
 * digest, and the same content scanned with the same ruleset on any platform
 * produces the same verdict, byte for byte (ADR-009). A committed verdict
 * snapshot is what proves it.
 *
 * The package is pure for the same reason `@mcpguard/core` is, and is separate
 * from it because ADR-002 says the hot path must be able to move to a native
 * module without dragging the rest of the engine along.
 */

export type {
  CompiledLexicons,
  Lexicons,
  LoadedRuleset,
  Pattern,
  Rule,
  RulesetData,
} from './ruleset/index.js';
export {
  compileRules,
  engineSatisfies,
  loadRuleset,
  RulesetEngineError,
  RulesetLintError,
  RulesetSchema,
  RulesetValidationError,
} from './ruleset/index.js';
export type { CompiledRuleset } from './scan.js';
export { byteLength, EMPTY_RULESET, scanContent } from './scan.js';
export type { CombinedScore, CombineInput } from './score/index.js';
export { combine, decide, familyCap, WEIGHT_SCALE } from './score/index.js';
export type {
  ContentItem,
  ContentKind,
  Edit,
  Family,
  Finding,
  ScanAction,
  ScanOptions,
  ScanVerdict,
  Severity,
  Span,
} from './types.js';
export { DETECT_VERSION } from './version.js';
