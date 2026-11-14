/**
 * Asking a compiled policy whether one call is permitted.
 *
 * This is permission only. Whether the *result* of the call is safe to hand
 * back is the scanner's question, asked afterwards on the way in.
 */
import type { CompiledPolicy, CompiledRule } from './compile.js';
import { toolKey } from './glob.js';
import type { RuleAction } from './schema.js';

/** What matching a call against the `tools` list produced. */
export interface AccessEvaluation {
  /** `undefined` when no rule matched. */
  readonly rule: CompiledRule | undefined;
  /** `tools[n]` when a rule matched, for the report and the audit record. */
  readonly matchedRule: string | undefined;
  /** The matched rule's action; `allow` when nothing matched. */
  readonly action: RuleAction;
  /** The roles the caller was evaluated as holding. */
  readonly roles: readonly string[];
  /** The rule's `note`, shown to the agent on a refusal. */
  readonly note: string | undefined;
}

/**
 * First match wins, and **an unmatched tool is allowed**.
 *
 * McpGuard is transparent until it is configured, so dropping it in front of an
 * existing server changes nothing until somebody writes rules. That is a
 * deliberate choice and it has a cost worth naming: a proxy that defaults to
 * deny would be safer and would also never be installed, and a security control
 * nobody runs protects nobody. Scanning, masking and the audit log are all on
 * by default — the thing that starts permissive is *permission*, which is the
 * one control that cannot be written without knowing the deployment.
 */
export function evaluateAccess(
  policy: CompiledPolicy,
  serverName: string,
  toolName: string,
  identity: string | undefined,
): AccessEvaluation {
  const roles = policy.rolesFor(identity);
  const rule = policy.match(serverName, toolName, roles);
  if (rule === undefined) {
    return {
      rule: undefined,
      matchedRule: undefined,
      action: 'allow',
      roles: [...roles],
      note: undefined,
    };
  }
  return {
    rule,
    matchedRule: rule.id,
    action: rule.rule.action,
    roles: [...roles],
    note: rule.rule.note,
  };
}

/** One call, as the combination detector remembers it. */
export interface CallMark {
  readonly serverName: string;
  readonly toolName: string;
  /** Milliseconds, from the injected clock. */
  readonly at: number;
}

/** A combination rule that fired, and the calls that satisfied it. */
export interface CombinationHit {
  readonly id: string;
  readonly action: 'deny' | 'flag';
  readonly note: string;
  /** One call per member glob, in the order the globs were written. */
  readonly evidence: readonly CallMark[];
}

/**
 * Looks for a dangerous combination in the recent history of one session.
 *
 * Every member glob has to be satisfied by a call inside the window, and one
 * call may satisfy only one glob — otherwise a single tool matching two loose
 * patterns would trip a rule about two capabilities all by itself. That is an
 * assignment problem, not a first-fit one: with `['fs__*', 'fs__read_*']` and the
 * calls `read_file`, `list_dir`, handing `read_file` to the broad glob first
 * leaves the narrow one with nothing, though `list_dir` + `read_file` is exactly
 * the pair the rule describes. Calls are therefore assigned to globs by bipartite
 * matching (augmenting paths), which finds a complete assignment whenever one
 * exists. Where several exist the earliest calls in `history` win, and the
 * evidence lists them in the order the globs were written.
 *
 * The scan is over the window, which is short by construction; the history
 * itself is bounded by the caller. There is no clock here — `now` is passed in,
 * because a rule that fires differently depending on when the audit is replayed
 * is not a rule anybody can verify.
 */
export function evaluateCombinations(
  policy: CompiledPolicy,
  history: readonly CallMark[],
  now: number,
): CombinationHit[] {
  const hits: CombinationHit[] = [];
  for (const { rule, matchers } of policy.combinations) {
    const since = now - rule.window;
    // For each glob, the history indexes it accepts, earliest first.
    const candidates = matchers.map((matcher) => {
      const accepted: number[] = [];
      history.forEach((mark, index) => {
        if (mark.at >= since && matcher.test(toolKey(mark.serverName, mark.toolName))) {
          accepted.push(index);
        }
      });
      return accepted;
    });
    // `owner[i]` is the glob currently holding history index `i`.
    const owner = new Map<number, number>();
    const assign = (glob: number, tried: Set<number>): boolean => {
      for (const index of candidates[glob] ?? []) {
        if (tried.has(index)) continue;
        tried.add(index);
        const holder = owner.get(index);
        if (holder === undefined || assign(holder, tried)) {
          owner.set(index, glob);
          return true;
        }
      }
      return false;
    };
    let complete = true;
    for (let glob = 0; glob < matchers.length; glob++) {
      if (!assign(glob, new Set())) {
        complete = false;
        break;
      }
    }
    if (!complete) continue;
    const evidence: CallMark[] = [];
    for (let glob = 0; glob < matchers.length; glob++) {
      for (const [index, holder] of owner) {
        const mark = history[index];
        if (holder === glob && mark !== undefined) evidence.push(mark);
      }
    }
    hits.push({ id: rule.id, action: rule.action, note: rule.note, evidence });
  }
  return hits;
}
