import { describe, expect, it } from 'vitest';
import { DIAGNOSTIC_PREFIX, Diagnostics } from './diagnostics.js';

/** The stderr writer, tested for the two things it promises: a prefix on every
 * line, and a rate limit that announces what it dropped rather than lying. */

class Capture {
  lines: string[] = [];
  write(chunk: string): boolean {
    this.lines.push(chunk);
    return true;
  }
}

describe('Diagnostics', () => {
  it('prefixes every diagnostic', () => {
    const sink = new Capture();
    new Diagnostics(sink).emit('injection_detected', { score: 80 });
    expect(sink.lines[0]).toContain(DIAGNOSTIC_PREFIX);
    expect(sink.lines[0]).toContain('injection_detected');
  });

  it('rate-limits within a window and reports the suppression', () => {
    const sink = new Capture();
    let now = 0;
    const diag = new Diagnostics(sink, { now: () => now, windowMs: 1_000, limit: 2 });
    diag.emit('a');
    diag.emit('b');
    diag.emit('c'); // suppressed
    diag.emit('d'); // suppressed
    now = 2_000;
    diag.emit('e'); // new window: flushes the suppression count first

    const joined = sink.lines.join('');
    expect(joined).toContain('diagnostics_suppressed');
    expect(joined).toContain('"count":2');
  });

  it('never rate-limits a block explanation', () => {
    const sink = new Capture();
    const diag = new Diagnostics(sink, { limit: 0 });
    diag.emit('flooded'); // suppressed
    diag.block('withheld: 3 findings');
    expect(sink.lines.join('')).toContain('withheld: 3 findings');
  });
});
