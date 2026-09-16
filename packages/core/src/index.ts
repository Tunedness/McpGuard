/**
 * `@mcpguard/core` — the decision engine.
 *
 * ## The purity invariant
 *
 * This package does **no I/O**. It never imports a transport, an MCP SDK,
 * `node:fs`, `node:net` or `node:child_process`. Its only runtime dependency is
 * `zod`; the only Node builtin it touches is `node:crypto`, for SHA-256 and
 * HMAC — computation, not I/O.
 *
 * That is not tidiness for its own sake. A security proxy's central claim is
 * that a decision it made six months ago can be reproduced by whoever audits
 * it, and a decision that reads a clock, a file or an environment variable
 * cannot be. Time arrives through an injected `Clock`, identity through an
 * `IdGenerator`, and the audit key through the caller.
 * `purity.test.ts` enforces all of it on every source file, and it is not to be
 * relaxed: the auditability claim rests entirely on it.
 */
export type { EventType, SecurityEvent, SecurityEventKind } from './domain/events.js';
export type {
  AccessEvaluation,
  CallMark,
  CombinationHit,
  CombinationRule,
  CompiledCombination,
  CompiledPolicy,
  CompiledRule,
  GuardPolicy,
  PolicyMode,
  RuleAction,
  ScanAction,
  ScanSettings,
  ScanSettingsOverride,
  ToolRule,
} from './policy/index.js';
export {
  compileGlob,
  compilePolicy,
  DURATION_MESSAGE,
  DURATION_PATTERN,
  defaultPolicy,
  evaluateAccess,
  evaluateCombinations,
  GuardPolicySchemaV1,
  globMatches,
  PolicyValidationError,
  parseDuration,
  parsePolicy,
  pathOf,
  toolKey,
} from './policy/index.js';
export type {
  AuditKey,
  AuditSink,
  Clock,
  IdGenerator,
  Ports,
  TelemetrySink,
} from './ports/index.js';
export { digestsEqual, hmacSha256, sha256 } from './util/hash.js';
export type { JsonValue } from './util/json.js';
export { stableStringify, toJsonValue } from './util/json.js';
export { CORE_VERSION } from './version.js';
