/**
 * The policy surface: the schema, the compiler and the two evaluators.
 *
 * Exported as its own entry point (`@mcpguard/core/policy`) so a tool that only
 * wants to validate a file — an editor plugin, a CI check — does not pull in
 * the audit chain and the manifest normaliser with it.
 */
export type { CompiledCombination, CompiledPolicy, CompiledRule } from './compile.js';
export { compilePolicy } from './compile.js';
export { DURATION_MESSAGE, DURATION_PATTERN, parseDuration } from './duration.js';
export type { AccessEvaluation, CallMark, CombinationHit } from './evaluate.js';
export { evaluateAccess, evaluateCombinations } from './evaluate.js';
export { compileGlob, globMatches, toolKey } from './glob.js';
export { defaultPolicy, PolicyValidationError, parsePolicy, pathOf } from './parse.js';
export type {
  CombinationRule,
  GuardPolicy,
  PolicyMode,
  RuleAction,
  ScanAction,
  ScanSettings,
  ScanSettingsOverride,
  ToolRule,
} from './schema.js';
export { GuardPolicySchemaV1 } from './schema.js';
