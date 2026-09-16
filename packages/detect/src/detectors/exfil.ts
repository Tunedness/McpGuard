/**
 * The exfiltration / egress-shape detector, and the conversation-frame detector.
 *
 * Egress fires only where a URL is auto-fetching or payload-carrying — a
 * markdown image, an `<img>`, an `<iframe>`, a query parameter that is a long
 * base64/hex run or is named like a data sink. A plain link scores nothing:
 * email footers and unsubscribe links look exactly like exfiltration otherwise,
 * and requiring an auto-fetch construct is what tells them apart.
 *
 * Frame fires on chat-template and role markers embedded in content, and needs
 * either two distinct markers or one plus something else, because a document
 * that is legitimately a chat log contains these too.
 */
import type { Normalized } from '../normalize/index.js';
import type { Finding } from '../types.js';
import { evidenceOf } from './evidence.js';

/** Auto-fetching or payload-carrying URL shapes. */
const BEACON =
  /!\[[^\]]*\]\((https?:\/\/[^)]+)\)|<img[^>]+src\s*=|<iframe[^>]+src\s*=|url\((https?:\/\/[^)]+)\)/gi;

/** A query parameter that is a long opaque run or a data-sink name. */
const SINK_PARAM = /[?&](q|d|c|data|prompt|context|text|payload)=[A-Za-z0-9+/=_-]{16,}/i;
const LONG_PARAM = /[?&][a-z]{1,12}=[A-Za-z0-9+/_-]{32,}/i;

/** Tool-invocation phrasing. */
const TOOL_CALL =
  /\b(call the \w+ tool|use \w+ with the|invoke the \w+ tool|send (it|the (transcript|contents|conversation)) to)\b/i;
const TOOL_CALL_TR = /\b(\w+ aracını çağır|\w+ ile gönder|aracını kullan)\b/i;

export function detectExfil(normalized: Normalized): Finding[] {
  const raw = normalized.raw;
  const findings: Finding[] = [];

  for (const match of raw.matchAll(BEACON)) {
    const url = match[1] ?? match[2] ?? match[0];
    const start = match.index ?? 0;
    const carriesData = SINK_PARAM.test(url) || LONG_PARAM.test(url);
    findings.push({
      ruleId: carriesData ? 'exfil.beacon-payload' : 'exfil.beacon',
      family: 'exfil',
      severity: carriesData ? 'high' : 'medium',
      weight: carriesData ? 720 : 460,
      span: { start, end: start + match[0].length },
      evidence: evidenceOf(raw, { start, end: start + match[0].length }),
    });
  }

  const toolCall = TOOL_CALL.exec(raw) ?? TOOL_CALL_TR.exec(raw);
  if (toolCall !== null) {
    const start = toolCall.index;
    findings.push({
      ruleId: 'exfil.tool-invocation',
      family: 'exfil',
      severity: 'high',
      weight: 640,
      span: { start, end: start + toolCall[0].length },
      evidence: evidenceOf(raw, { start, end: start + toolCall[0].length }),
    });
  }

  return findings;
}

/** Chat-template and role markers embedded in content. */
const FRAME_MARKERS: readonly { re: RegExp; id: string }[] = [
  { re: /<\|im_(start|end)\|>/g, id: 'frame.chatml' },
  { re: /<\|(system|user|assistant)\|>/g, id: 'frame.role-tag' },
  { re: /\[INST\]|\[\/INST\]|<<SYS>>/g, id: 'frame.llama' },
  { re: /^###\s*(system|sistem)\s*:/gim, id: 'frame.heading-system' },
  { re: /^(human|assistant|system)\s*:/gim, id: 'frame.role-line' },
  { re: /<(system|instructions)>/gi, id: 'frame.xml-system' },
  { re: /---\s*(yeni talimatlar|new instructions|end of document)\s*---/gi, id: 'frame.banner' },
];

export function detectFrame(normalized: Normalized): Finding[] {
  const raw = normalized.raw;
  const hits: { id: string; start: number; end: number }[] = [];
  for (const marker of FRAME_MARKERS) {
    for (const match of raw.matchAll(marker.re)) {
      const start = match.index ?? 0;
      hits.push({ id: marker.id, start, end: start + match[0].length });
    }
  }
  // One marker is not enough: a chat log or a prompt-engineering doc legitimately
  // carries one. Two distinct markers, or a doc that is not doc-shaped with one,
  // is the injection shape.
  const distinct = new Set(hits.map((h) => h.id));
  if (distinct.size < 2 && !(hits.length >= 1 && !normalized.shape.docLike)) return [];

  const first = hits[0];
  if (first === undefined) return [];
  return [
    {
      ruleId: 'frame.role-injection',
      family: 'frame',
      severity: distinct.size >= 2 ? 'high' : 'medium',
      weight: distinct.size >= 2 ? 600 : 380,
      span: { start: first.start, end: first.end },
      evidence: evidenceOf(raw, { start: first.start, end: first.end }),
    },
  ];
}
