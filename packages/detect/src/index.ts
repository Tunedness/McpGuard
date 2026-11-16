/**
 * `@tunedness/mcpguard-detect` — the tier-1 detection engine.
 *
 * Deterministic by construction, and that word is load-bearing here rather than
 * decorative: the score path is integer arithmetic, the ruleset is data with a
 * digest, and the same content scanned with the same ruleset on any platform
 * produces the same verdict, byte for byte (ADR-009). A committed verdict
 * snapshot is what proves it.
 *
 * The package is pure for the same reason `@tunedness/mcpguard-core` is, and is separate
 * from it because ADR-002 says the hot path must be able to move to a native
 * module without dragging the rest of the engine along.
 */

export type {
  AttributeKind,
  BaseKind,
  CompiledPiiData,
  HealthKind,
  MaskConfig,
  PiiConfig,
  PiiData,
  PiiKind,
  PiiMatch,
  PiiProfile,
} from './pii/index.js';
export {
  ATTRIBUTE_KINDS,
  BASE_KINDS,
  cardScheme,
  HEALTH_KINDS,
  isPlausibleSsn,
  isValidCalendarDate,
  isValidGs1CheckDigit,
  isValidIbanChecksum,
  isValidLuhn,
  isValidMbiShape,
  isValidTckn,
  isValidVkn,
  maskEdits,
  maskFor,
  PII_KINDS,
  PiiDataMissingError,
  recognize,
} from './pii/index.js';
export type {
  CompiledLexicons,
  Lexicons,
  LoadedRuleset,
  Pattern,
  PiiDataSection,
  Rule,
  RulesetData,
} from './ruleset/index.js';
export {
  compileRules,
  engineSatisfies,
  loadRuleset,
  PiiDataSchema,
  RulesetEngineError,
  RulesetLintError,
  RulesetSchema,
  RulesetValidationError,
} from './ruleset/index.js';
export type { CompiledRuleset } from './scan.js';
export { byteLength, EMPTY_RULESET, scanContent } from './scan.js';
export type { CombinedScore, CombineInput } from './score/index.js';
export { combine, decide, familyCap, WEIGHT_SCALE } from './score/index.js';
export { applyEdits, buildStripEdits, STRIP_MARKER } from './strip.js';
export type {
  ContentItem,
  ContentKind,
  Edit,
  Family,
  Finding,
  PiiFinding,
  PiiScanConfig,
  ScanAction,
  ScanOptions,
  ScanVerdict,
  Severity,
  Span,
} from './types.js';
export { DETECT_VERSION } from './version.js';
