/**
 * What a command is allowed to know about the outside world.
 *
 * Every command takes a {@link CliContext} and returns an exit code. That is
 * what makes them testable without intercepting a global — and, in `wrap` mode,
 * what keeps a stray diagnostic out of the JSON-RPC stream `process.stdout`
 * becomes. `discipline.test.ts` fails the build if any source file other than
 * `main.ts` reaches for the process.
 */

/** The minimum of a writable stream the CLI needs. */
export interface Writer {
  write(chunk: string): unknown;
}

/** Everything a command may read from its environment. */
export interface CliContext {
  readonly argv: readonly string[];
  /** Command output. **In wrap mode this is the agent's JSON-RPC stream.** */
  readonly stdout: Writer;
  /** Diagnostics, warnings and errors. Always safe to write to. */
  readonly stderr: Writer;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly cwd: string;
}

/** Collects what was written, for tests. */
export class StringWriter implements Writer {
  #chunks: string[] = [];

  write(chunk: string): boolean {
    this.#chunks.push(chunk);
    return true;
  }

  get text(): string {
    return this.#chunks.join('');
  }

  get lines(): string[] {
    const text = this.text;
    return text === '' ? [] : text.replace(/\n$/, '').split('\n');
  }

  clear(): void {
    this.#chunks = [];
  }
}

/** Writes one line, terminator included. */
export function writeLine(writer: Writer, text = ''): void {
  writer.write(`${text}\n`);
}

/** Writes several lines in one call. */
export function writeLines(writer: Writer, lines: readonly string[]): void {
  if (lines.length === 0) return;
  writer.write(`${lines.join('\n')}\n`);
}
