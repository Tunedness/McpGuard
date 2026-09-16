/**
 * The guarded seams: what happens to a tool call, a tool list and a resource
 * read on the way through.
 *
 * This is the one place in the proxy that knows both engines. It composes the
 * decision engine's access evaluation and the detection engine's content scan
 * into the three things the proxy does: refuse a call the policy denies, scan
 * and mask a result before it reaches the model, and pin a manifest so a
 * rug-pull is caught. The transport is not here — this takes plain values and
 * returns plain values, so it can be tested without a socket.
 */
import type { AccessEvaluation, CompiledPolicy } from '@mcpguard/core';
import { evaluateAccess } from '@mcpguard/core';
import type { CompiledRuleset, ScanOptions, ScanVerdict } from '@mcpguard/detect';
import { scanContent } from '@mcpguard/detect';
import { extractText, type ResultLike, replaceText } from './content.js';

/** Everything the guard needs that the host injects once. */
export interface GuardContext {
  readonly policy: CompiledPolicy;
  readonly ruleset: CompiledRuleset;
  readonly scanOptions: ScanOptions;
  readonly enforce: boolean;
}

/** What guarding one call's result produced. */
export interface GuardedResult {
  /** The result to forward. Masked and possibly stripped. */
  readonly result: ResultLike;
  /** The worst action any content block reached. */
  readonly action: 'allow' | 'flag' | 'strip' | 'block';
  /** The scan verdicts, one per scanned text block. */
  readonly verdicts: readonly ScanVerdict[];
}

const ACTION_RANK: Record<GuardedResult['action'], number> = {
  allow: 0,
  flag: 1,
  strip: 2,
  block: 3,
};

/** Decides whether one tool call is permitted, before it is forwarded. */
export function guardCall(
  context: GuardContext,
  serverName: string,
  toolName: string,
  identity: string | undefined,
): AccessEvaluation {
  return evaluateAccess(context.policy, serverName, toolName, identity);
}

/**
 * Scans and masks a result's text blocks, returning the guarded result.
 *
 * Each text block is scanned independently and its guarded text put back; the
 * call's action is the worst any block reached. In observe mode (`enforce`
 * false) the action is computed and the content is still masked and stripped —
 * masking is not enforcement, it is data hygiene — but a `block` is downgraded
 * to `flag` so nothing is withheld while the operator is still measuring.
 */
export function guardResult(
  context: GuardContext,
  serverName: string,
  toolName: string,
  result: ResultLike,
): GuardedResult {
  const refs = extractText(result);
  const verdicts: ScanVerdict[] = [];
  const guarded = new Map<string, string>();
  let action: GuardedResult['action'] = 'allow';

  for (const ref of refs) {
    const verdict = scanContent(
      { id: ref.id, text: ref.text, kind: 'tool_result', channel: `${serverName}__${toolName}` },
      context.ruleset,
      context.scanOptions,
    );
    verdicts.push(verdict);
    guarded.set(ref.id, verdict.text);
    if (ACTION_RANK[verdict.action] > ACTION_RANK[action]) action = verdict.action;
  }

  const effective = context.enforce ? action : action === 'block' ? 'flag' : action;
  const forwarded = replaceText(result, guarded);
  return { result: forwarded, action: effective, verdicts };
}

/** The content kind a resource read is scanned as. */
export function guardResource(
  context: GuardContext,
  serverName: string,
  uri: string,
  result: ResultLike,
): GuardedResult {
  // A resource read scans the same way a tool result does, tagged as `resource`
  // so a rule scoped to that kind applies.
  const refs = extractText(result);
  const verdicts: ScanVerdict[] = [];
  const guarded = new Map<string, string>();
  let action: GuardedResult['action'] = 'allow';
  for (const ref of refs) {
    const verdict = scanContent(
      { id: ref.id, text: ref.text, kind: 'resource', channel: `${serverName}__${uri}` },
      context.ruleset,
      context.scanOptions,
    );
    verdicts.push(verdict);
    guarded.set(ref.id, verdict.text);
    if (ACTION_RANK[verdict.action] > ACTION_RANK[action]) action = verdict.action;
  }
  const effective = context.enforce ? action : action === 'block' ? 'flag' : action;
  return { result: replaceText(result, guarded), action: effective, verdicts };
}

/** The stub content a blocked result is replaced with. No attacker bytes. */
export function blockedResult(
  action: string,
  findingCount: number,
  rulesetVersion: string,
): ResultLike {
  return {
    isError: true,
    content: [
      {
        type: 'text',
        text: `[mcpguard] content withheld · ${findingCount} finding(s) · ruleset ${rulesetVersion} · action ${action}`,
      },
    ],
  };
}
