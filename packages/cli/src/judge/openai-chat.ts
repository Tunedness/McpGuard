/**
 * The OpenAI-compatible chat adapter (ADR-012, H-A).
 *
 * One `POST /v1/chat/completions` through the global `fetch`: Ollama,
 * llama-server, vLLM and LM Studio all answer it, and the proxy gains no npm
 * dependency. The adapter's whole output is a {@link JudgeResult}; it holds no
 * reference to the content it was handed, so it has no way to alter what is
 * forwarded. Everything the model says is checked against a closed shape, and
 * anything else, a stray field, a code fence, a number out of range, is an
 * `error` and tier 1's decision stands.
 *
 * No redirects are followed: a loopback endpoint that redirected elsewhere would
 * walk around the `allow_remote` rule the policy enforced on the URL.
 */
import { randomUUID } from 'node:crypto';
import type { Judge, JudgeOutcome, JudgeRequest, JudgeResult } from '@tunedness/mcpguard-core';
import { buildMessages, VERDICT_SCHEMA } from './prompt.js';

/** The most response bytes read. A verdict is a few dozen. */
export const MAX_RESPONSE_BYTES = 65_536;

/** How the adapter is built. */
export interface OpenAiChatOptions {
  readonly endpoint: string;
  readonly model: string;
  readonly modelRevision?: string | undefined;
  /** Extra request headers (an API key). Never logged, never recorded. */
  readonly headers?: Readonly<Record<string, string>> | undefined;
  readonly maxInputBytes: number;
  /** Sent as `reasoning_effort`. `omit`, or absent, leaves the field out of the request. */
  readonly reasoningEffort?: 'none' | 'minimal' | 'low' | 'medium' | 'high' | 'omit' | undefined;
  /** The answer's token budget. Default 32: the answer is one small JSON object. */
  readonly maxTokens?: number | undefined;
  /** Injected for tests; defaults to the global `fetch`. */
  readonly fetch?: typeof fetch | undefined;
  /** Injected for tests; defaults to `randomUUID`. */
  readonly newBoundary?: (() => string) | undefined;
}

/** What {@link sampleForJudge} produced. */
export interface Sampled {
  readonly text: string;
  readonly truncated: boolean;
}

/**
 * Fits `text` into `maxBytes`: whole when it fits, otherwise its head and its tail.
 *
 * The tail is kept for the same reason the scanner keeps it: instructions
 * appended after a large clean payload are an attack family.
 */
export function sampleForJudge(text: string, maxBytes: number): Sampled {
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= maxBytes) return { text, truncated: false };
  const head = Math.floor(maxBytes / 2);
  const tail = maxBytes - head;
  return {
    text: `${bytes.subarray(0, head).toString('utf8')}\n[...]\n${bytes
      .subarray(bytes.length - tail)
      .toString('utf8')}`,
    truncated: true,
  };
}

/** The model's text content, parsed strictly, or `undefined` when it is anything else. */
export function parseVerdict(
  content: string,
): { label: 'injection' | 'benign'; confidence: number } | undefined {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== 'confidence' || keys[1] !== 'label') return undefined;
  const { label, confidence } = value as { label: unknown; confidence: unknown };
  if (label !== 'injection' && label !== 'benign') return undefined;
  if (typeof confidence !== 'number' || !Number.isInteger(confidence)) return undefined;
  if (confidence < 0 || confidence > 100) return undefined;
  return { label, confidence };
}

/** A model name safe to copy into a record, or `undefined`. */
function safeModelName(value: unknown): string | undefined {
  return typeof value === 'string' && /^[\w.:/@+-]{1,128}$/.test(value) ? value : undefined;
}

/** Reads a response body up to {@link MAX_RESPONSE_BYTES}, or `undefined` when it is longer. */
async function readCapped(response: Response): Promise<string | undefined> {
  if (response.body === null) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {});
      return undefined;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function isAbort(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'name' in error &&
    (error.name === 'TimeoutError' || error.name === 'AbortError')
  );
}

/** The adapter. */
export class OpenAiChatJudge implements Judge {
  readonly adapter = 'openai_chat';
  readonly model: string;
  readonly modelRevision: string | undefined;
  readonly #options: OpenAiChatOptions;
  readonly #fetch: typeof fetch;
  readonly #boundary: () => string;

  constructor(options: OpenAiChatOptions) {
    this.#options = options;
    this.model = options.model;
    this.modelRevision = options.modelRevision;
    this.#fetch = options.fetch ?? fetch;
    this.#boundary = options.newBoundary ?? randomUUID;
  }

  async judge(request: JudgeRequest, timeoutMs: number): Promise<JudgeResult> {
    const started = performance.now();
    const sampled = sampleForJudge(request.text, this.#options.maxInputBytes);
    const finish = (outcome: JudgeOutcome, model = this.model): JudgeResult => ({
      outcome,
      model,
      ...(this.#options.modelRevision !== undefined
        ? { modelRevision: this.#options.modelRevision }
        : {}),
      latencyMs: Math.max(0, Math.round(performance.now() - started)),
      truncated: sampled.truncated,
      cached: false,
    });

    try {
      const response = await this.#fetch(this.#options.endpoint, {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
        headers: { ...this.#options.headers, 'content-type': 'application/json' },
        body: JSON.stringify({
          model: this.#options.model,
          messages: buildMessages(request, sampled.text, this.#boundary()),
          temperature: 0,
          max_tokens: this.#options.maxTokens ?? 32,
          stream: false,
          ...(this.#options.reasoningEffort !== undefined &&
          this.#options.reasoningEffort !== 'omit'
            ? { reasoning_effort: this.#options.reasoningEffort }
            : {}),
          response_format: {
            type: 'json_schema',
            json_schema: { name: 'verdict', strict: true, schema: VERDICT_SCHEMA },
          },
        }),
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        return finish({ kind: 'error', reason: `http_${response.status}` });
      }
      const body = await readCapped(response);
      if (body === undefined) return finish({ kind: 'error', reason: 'response_too_large' });
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch {
        return finish({ kind: 'error', reason: 'bad_envelope' });
      }
      if (typeof parsed !== 'object' || parsed === null) {
        return finish({ kind: 'error', reason: 'bad_envelope' });
      }
      const envelope = parsed as {
        model?: unknown;
        choices?: Array<{ finish_reason?: unknown; message?: { content?: unknown } }>;
      };
      const model = safeModelName(envelope.model) ?? this.model;
      const choice = Array.isArray(envelope.choices) ? envelope.choices[0] : undefined;
      const content = choice?.message?.content;
      if (typeof content !== 'string')
        return finish({ kind: 'error', reason: 'no_content' }, model);
      const verdict = parseVerdict(content);
      if (verdict !== undefined) return finish({ kind: 'verdict', ...verdict }, model);
      // Said apart, because each has a different fix: a model that ran out of tokens
      // (usually thinking first) wants a larger budget or `reasoning_effort: none`,
      // while one that answered in the wrong shape wants a different model or prompt.
      if (choice?.finish_reason === 'length') {
        return finish({ kind: 'error', reason: 'output_truncated' }, model);
      }
      if (content.trim() === '') return finish({ kind: 'error', reason: 'empty_content' }, model);
      return finish({ kind: 'error', reason: 'unparseable' }, model);
    } catch (error) {
      if (isAbort(error)) return finish({ kind: 'timeout' });
      return finish({ kind: 'error', reason: 'network' });
    }
  }
}
