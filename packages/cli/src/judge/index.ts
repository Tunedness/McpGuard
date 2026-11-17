/**
 * Building the judge a policy asks for.
 *
 * Off is the default and the cheap case: no adapter, no limiter, nothing that
 * opens a socket. `buildJudge` is the one place a host turns `policy.judge` into
 * a {@link Judge}, so `wrap` and `serve` cannot disagree about what the settings
 * mean.
 */
import { type GuardPolicy, type Judge, NULL_JUDGE } from '@tunedness/mcpguard-core';
import { LimitedJudge } from './limiter.js';
import { OpenAiChatJudge } from './openai-chat.js';

export { applyTier2, type Tier2Input, type Tier2Outcome } from './gate.js';
export { LimitedJudge } from './limiter.js';
export { OpenAiChatJudge, parseVerdict, sampleForJudge } from './openai-chat.js';

/** What a host supplies that the policy cannot. */
export interface JudgeHost {
  /** The headers `judge.headers_env` named, already read from the environment. */
  readonly headers: Readonly<Record<string, string>>;
  readonly clock: () => number;
  /** Told once when the breaker opens. */
  readonly onUnavailable: (info: { failures: number; openForMs: number }) => void;
  /** Injected for tests. */
  readonly fetch?: typeof fetch | undefined;
  readonly newBoundary?: (() => string) | undefined;
}

/** The judge the policy configures, or {@link NULL_JUDGE} when it is off. */
export function buildJudge(policy: GuardPolicy, host: JudgeHost): Judge {
  const settings = policy.judge;
  if (!settings.enabled) return NULL_JUDGE;
  // The schema refuses an enabled judge without these, so this is unreachable from a
  // parsed policy; it is here so a hand-built one cannot quietly run without a judge.
  if (settings.endpoint === undefined || settings.model === undefined) {
    throw new Error('judge.enabled needs judge.endpoint and judge.model');
  }
  return new LimitedJudge({
    inner: new OpenAiChatJudge({
      endpoint: settings.endpoint,
      model: settings.model,
      modelRevision: settings.model_revision,
      headers: host.headers,
      maxInputBytes: settings.max_input_bytes,
      reasoningEffort: settings.reasoning_effort,
      maxTokens: settings.max_tokens,
      fetch: host.fetch,
      newBoundary: host.newBoundary,
    }),
    maxInflight: settings.max_inflight,
    failureThreshold: settings.circuit_failures,
    openForMs: settings.circuit_open_for,
    clock: host.clock,
    onUnavailable: host.onUnavailable,
  });
}
