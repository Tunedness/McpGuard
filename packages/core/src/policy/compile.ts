/**
 * Turning a validated policy into one that can be asked questions cheaply.
 *
 * Every glob in the document is compiled once, here. The hot path — one
 * `tools/call`, up to 20 ms of budget shared with a whole content scan — never
 * builds a regex, and `purity.test.ts` holds that line by banning `new RegExp(`
 * outside this file and `glob.ts`.
 */
import { compileGlob, toolKey } from './glob.js';
import type {
  CombinationRule,
  GuardPolicy,
  ScanSettings,
  ScanSettingsOverride,
  ToolRule,
} from './schema.js';

/** One access rule, with its glob already compiled and its index remembered. */
export interface CompiledRule {
  /** `tools[n]`, so a report can name the line the operator wrote. */
  readonly id: string;
  readonly rule: ToolRule;
  readonly matcher: RegExp;
  readonly roles: ReadonlySet<string>;
}

/** One combination rule, with every member glob compiled. */
export interface CompiledCombination {
  readonly rule: CombinationRule;
  readonly matchers: readonly RegExp[];
}

/** One scan override, with its glob compiled and its settings already merged. */
interface CompiledScanOverride {
  readonly matcher: RegExp;
  readonly settings: ScanSettings;
}

/** A policy that has been asked all of its compile-time questions. */
export interface CompiledPolicy {
  readonly policy: GuardPolicy;
  readonly rules: readonly CompiledRule[];
  readonly combinations: readonly CompiledCombination[];
  /** First matching rule for this tool and this caller's roles, or `undefined`. */
  match(serverName: string, toolName: string, roles: ReadonlySet<string>): CompiledRule | undefined;
  /** Fully merged scan settings for one tool. Never returns a partial. */
  scanFor(serverName: string, toolName: string): ScanSettings;
  /** Roles the policy grants a caller identity. */
  rolesFor(identity: string | undefined): ReadonlySet<string>;
}

const NO_ROLES: ReadonlySet<string> = new Set();

export function compilePolicy(policy: GuardPolicy): CompiledPolicy {
  const rules: CompiledRule[] = policy.tools.map((rule, index) => ({
    id: `tools[${index}]`,
    rule,
    matcher: compileGlob(rule.match),
    roles: new Set(rule.roles),
  }));

  const combinations: CompiledCombination[] = policy.combinations.map((rule) => ({
    rule,
    matchers: rule.all_of.map(compileGlob),
  }));

  const defaults = policy.scan.default;
  const overrides: CompiledScanOverride[] = Object.entries(policy.scan.tools).map(
    ([pattern, partial]) => ({
      matcher: compileGlob(pattern),
      // Merged at compile time so the hot path reads one flat object and can
      // never see a half-specified setting.
      settings: mergeScanSettings(defaults, partial),
    }),
  );

  const roleMap = new Map<string, ReadonlySet<string>>(
    Object.entries(policy.roles).map(([identity, roles]) => [identity, new Set(roles)]),
  );

  return {
    policy,
    rules,
    combinations,
    match(serverName, toolName, roles) {
      const key = toolKey(serverName, toolName);
      for (const rule of rules) {
        if (!rule.matcher.test(key)) continue;
        // An empty `roles` list on a rule means "every caller". A non-empty one
        // is a filter, so a rule scoped to `admin` is simply not this caller's
        // rule and the search continues past it.
        if (rule.roles.size > 0 && !intersects(rule.roles, roles)) continue;
        return rule;
      }
      return undefined;
    },
    scanFor(serverName, toolName) {
      const key = toolKey(serverName, toolName);
      for (const override of overrides) {
        if (override.matcher.test(key)) return override.settings;
      }
      return defaults;
    },
    rolesFor(identity) {
      if (identity === undefined) return NO_ROLES;
      return roleMap.get(identity) ?? NO_ROLES;
    },
  };
}

function intersects(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  for (const value of a) if (b.has(value)) return true;
  return false;
}

/**
 * Lays a per-tool override over the defaults, field by field.
 *
 * Written out rather than spread, because an override key present-but-undefined
 * — which is what a YAML key with no value becomes — must leave the default
 * standing rather than erase it. A spread would erase it, and the field it
 * would erase most often is `action`, whose default is the only thing stopping
 * the proxy from blocking traffic nobody asked it to block.
 */
function mergeScanSettings(defaults: ScanSettings, override: ScanSettingsOverride): ScanSettings {
  return {
    action: override.action ?? defaults.action,
    flag_at: override.flag_at ?? defaults.flag_at,
    block_at: override.block_at ?? defaults.block_at,
    max_bytes: override.max_bytes ?? defaults.max_bytes,
    on_degraded: override.on_degraded ?? defaults.on_degraded,
  };
}
