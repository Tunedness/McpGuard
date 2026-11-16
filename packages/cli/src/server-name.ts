/**
 * Whether the name a server runs under is one the policy knows.
 *
 * `servers.<name>` is looked up by the name the proxy gives the server it fronts:
 * `--name` for `wrap` and for the command-line upstream of `serve`, the key itself
 * for a server the policy defines. A name that matches nothing is not an error to
 * the lookup, it is just a server the policy says nothing about, so every rule
 * written under `servers.<name>` quietly stops applying to it. With a role list
 * under `servers` that is the access control falling away on a typo. A policy that
 * has a `servers` section is therefore taken to mean to name every server it will
 * front, and under `mode: enforce` a name it does not carry stops the start.
 */
import type { GuardPolicy, SecurityEvent, TelemetrySink } from '@tunedness/mcpguard-core';
import { CliError, EXIT } from './errors.js';

/** The longest server name written into a record. */
const MAX_NAME_LENGTH = 64;
/** The most policy server names listed in a message. */
const MAX_LISTED = 20;

/** What a server name that matches no `servers` entry looks like, for the diagnostics. */
export interface UnmatchedServer {
  readonly server: string;
  /** The `servers` keys the policy does carry, capped. */
  readonly defined: readonly string[];
  readonly via: 'wrap' | 'serve';
  readonly hint: string;
}

/**
 * Checks `serverName` against the policy's `servers` section.
 *
 * - No `servers` section, or the name is one of its keys: nothing to say.
 * - Otherwise under `mode: enforce`: throws, with the policy exit code.
 * - Otherwise (`mode: flag`): returns what to report, and the start goes on.
 *
 * The key is looked up as an own property, because `constructor` and `toString`
 * are not servers the policy named.
 *
 * @throws {CliError} when the policy enforces and does not name this server.
 */
export function checkServerName(
  policy: GuardPolicy,
  serverName: string,
  via: 'wrap' | 'serve',
  nameGiven: boolean,
): UnmatchedServer | undefined {
  const keys = Object.keys(policy.servers);
  if (keys.length === 0 || Object.hasOwn(policy.servers, serverName)) return undefined;

  const shown = serverName.slice(0, MAX_NAME_LENGTH);
  const defined = keys.slice(0, MAX_LISTED);
  const hint = `to run it unrestricted, add an empty entry to the policy: servers: { ${shown}: {} }`;
  const unmatched: UnmatchedServer = { server: shown, defined, via, hint };
  if (policy.mode !== 'enforce') return unmatched;

  throw new CliError(
    `the server is named "${shown}"${nameGiven ? '' : ' (no --name given)'}, and the policy's servers section does not name it (it names: ${defined.join(', ')})`,
    {
      exitCode: EXIT.policy,
      hints: [
        'with mode: enforce, a server the policy does not name would run without the rules written under servers.<name>, roles included',
        nameGiven
          ? '--name must be one of those keys'
          : 'give it --name <key>, one of those keys, if it is one of them',
        hint,
      ],
    },
  );
}

/**
 * Says so, in the two places a start-up fact goes: the diagnostic stream and the
 * telemetry sink. Under `flag` the start goes on, and this is the only trace.
 */
export function reportUnmatchedServer(
  unmatched: UnmatchedServer,
  out: (event: string, detail: Record<string, unknown>) => void,
  telemetry: TelemetrySink,
  clock: () => number,
  sessionId: string,
): void {
  out('server_unmatched', {
    server: unmatched.server,
    defined: unmatched.defined,
    action: 'flag',
    hint: `mode: flag lets it run, without the rules written under servers.<name>; ${unmatched.hint}`,
  });
  const event: SecurityEvent = {
    type: 'security_event',
    kind: 'server_unmatched',
    at: clock(),
    sessionId,
    serverName: unmatched.server,
    toolName: undefined,
    score: undefined,
    action: 'flag',
    evidence: [`servers.${unmatched.server}`],
  };
  telemetry.emit(event);
}
