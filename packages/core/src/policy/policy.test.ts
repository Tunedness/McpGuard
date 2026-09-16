import { describe, expect, it } from 'vitest';
import { compilePolicy } from './compile.js';
import { DURATION_MESSAGE, parseDuration } from './duration.js';
import { evaluateAccess, evaluateCombinations } from './evaluate.js';
import { compileGlob, globMatches, toolKey } from './glob.js';
import { defaultPolicy, PolicyValidationError, parsePolicy, pathOf } from './parse.js';

/**
 * The policy layer, read the way an operator reads it: what does this file mean
 * at three in the morning, and what does it mean when a field is missing.
 */

describe('glob', () => {
  it('anchors at both ends', () => {
    expect(globMatches('shell__*', 'shell__exec')).toBe(true);
    expect(globMatches('shell__*', 'my_shell__exec')).toBe(false);
  });

  it('lets * cross underscores, so a namespace prefix covers its tools', () => {
    expect(globMatches('*__delete_*', 'db__delete_row')).toBe(true);
  });

  it('matches everything with a bare star', () => {
    expect(globMatches('*', 'anything__at_all')).toBe(true);
  });

  it('treats ? as exactly one character', () => {
    expect(globMatches('fs__read?', 'fs__reads')).toBe(true);
    expect(globMatches('fs__read?', 'fs__read')).toBe(false);
  });

  it('escapes regex metacharacters instead of honouring them', () => {
    // A tool called `a.b` must not be matched by a pattern written for `axb`.
    expect(globMatches('fs__a.b', 'fs__axb')).toBe(false);
    expect(globMatches('fs__a.b', 'fs__a.b')).toBe(true);
    expect(compileGlob('a+b').test('a+b')).toBe(true);
  });

  it('spells a tool key the way MCP namespaces one', () => {
    expect(toolKey('github', 'get_issue')).toBe('github__get_issue');
  });
});

describe('parseDuration', () => {
  it.each([
    ['500ms', 500],
    ['30s', 30_000],
    ['10m', 600_000],
    ['2h', 7_200_000],
    ['1d', 86_400_000],
  ])('reads %s as %d ms', (input, expected) => {
    expect(parseDuration(input)).toBe(expected);
  });

  it('passes a plain number through as milliseconds', () => {
    expect(parseDuration(1500)).toBe(1500);
  });

  it('refuses a shape it does not recognise, and says what it wanted', () => {
    expect(() => parseDuration('10 minutes')).toThrow(DURATION_MESSAGE);
  });
});

describe('parsePolicy', () => {
  it('turns `{ version: 1 }` into a complete policy', () => {
    const policy = defaultPolicy();

    // Every default is safe: nothing is denied, nothing is rewritten, and the
    // posture is observation rather than enforcement.
    expect(policy.mode).toBe('flag');
    expect(policy.scan.default.action).toBe('flag');
    expect(policy.tools).toEqual([{ match: '*', action: 'allow', roles: [] }]);
    expect(policy.audit.enabled).toBe(true);
    expect(policy.telemetry.enabled).toBe(false);
  });

  it('never sends a checkpoint to stdout', () => {
    // In wrap mode stdout is the agent's JSON-RPC stream. One stray byte there
    // corrupts every frame after it, with the blame landing on the server.
    expect(defaultPolicy().audit.checkpoint_to).toBe('stderr');
    expect(() => parsePolicy({ version: 1, audit: { checkpoint_to: 'stdout' } })).toThrow(
      PolicyValidationError,
    );
  });

  it('rejects a misspelled key rather than ignoring it', () => {
    // A security control that silently did not apply is the worst outcome
    // available, so every object in the schema is strict.
    expect(() => parsePolicy({ version: 1, mod: 'enforce' })).toThrow(PolicyValidationError);
  });

  it('rejects an unknown version', () => {
    expect(() => parsePolicy({ version: 2 })).toThrow(PolicyValidationError);
  });

  it('parses durations to milliseconds', () => {
    const policy = parsePolicy({ version: 1, session: { idle_timeout: '15m' } });

    expect(policy.session.idle_timeout).toBe(900_000);
  });

  it('requires a reason before a rule can be weighted to nothing', () => {
    // Disabling a detection rule is a decision somebody should have to write
    // down, because the audit log is going to quote it back at them.
    expect(() => parsePolicy({ version: 1, scan: { rules: { 'inj.x': { weight: 0 } } } })).toThrow(
      PolicyValidationError,
    );
    expect(
      parsePolicy({
        version: 1,
        scan: { rules: { 'inj.x': { weight: 0, reason: 'our wiki mirrors OWASP text' } } },
      }).scan.rules['inj.x']?.weight,
    ).toBe(0);
  });

  it('collects every issue, not just the first', () => {
    try {
      parsePolicy({ version: 1, mode: 'nope', session: { idle_timeout: 'soon' } });
      expect.unreachable('the policy should not have validated');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyValidationError);
      expect((error as PolicyValidationError).issues.length).toBeGreaterThan(1);
    }
  });
});

describe('pathOf', () => {
  it('writes a path the way the operator wrote it in the file', () => {
    expect(pathOf(['tools', 0, 'match'])).toBe('tools[0].match');
    expect(pathOf([])).toBe('(root)');
    expect(pathOf([0])).toBe('[0]');
  });
});

describe('evaluateAccess', () => {
  it('allows a tool no rule mentions', () => {
    // Transparent until configured: a proxy that defaults to deny is safer and
    // is also never installed.
    const policy = compilePolicy(parsePolicy({ version: 1, tools: [] }));

    expect(evaluateAccess(policy, 'fs', 'read_file', undefined).action).toBe('allow');
  });

  it('takes the first matching rule and names it', () => {
    const policy = compilePolicy(
      parsePolicy({
        version: 1,
        tools: [
          { match: 'fs__delete_*', action: 'deny', note: 'destructive' },
          { match: '*', action: 'allow' },
        ],
      }),
    );
    const decision = evaluateAccess(policy, 'fs', 'delete_file', undefined);

    expect(decision.action).toBe('deny');
    expect(decision.matchedRule).toBe('tools[0]');
    expect(decision.note).toBe('destructive');
  });

  it('skips a rule scoped to roles the caller does not hold', () => {
    const policy = compilePolicy(
      parsePolicy({
        version: 1,
        roles: { 'ci-bot': ['ci'] },
        tools: [
          { match: 'fs__*', action: 'allow', roles: ['admin'] },
          { match: 'fs__*', action: 'deny' },
        ],
      }),
    );

    expect(evaluateAccess(policy, 'fs', 'read_file', 'ci-bot').action).toBe('deny');
    expect(evaluateAccess(policy, 'fs', 'read_file', 'admin-person').action).toBe('deny');
  });

  it('applies a role-scoped rule to a caller who does hold the role', () => {
    const policy = compilePolicy(
      parsePolicy({
        version: 1,
        roles: { alice: ['admin'] },
        tools: [
          { match: 'fs__*', action: 'allow', roles: ['admin'] },
          { match: 'fs__*', action: 'deny' },
        ],
      }),
    );
    const decision = evaluateAccess(policy, 'fs', 'read_file', 'alice');

    expect(decision.action).toBe('allow');
    expect(decision.roles).toEqual(['admin']);
  });
});

describe('evaluateCombinations', () => {
  const policy = compilePolicy(
    parsePolicy({
      version: 1,
      combinations: [
        {
          id: 'read-then-egress',
          all_of: ['fs__read_*', 'web__fetch'],
          action: 'deny',
          window: '10m',
          note: 'a session that reads local files and then reaches the network',
        },
      ],
    }),
  );

  it('fires when every member is present inside the window', () => {
    const hits = evaluateCombinations(
      policy,
      [
        { serverName: 'fs', toolName: 'read_file', at: 1_000 },
        { serverName: 'web', toolName: 'fetch', at: 2_000 },
      ],
      3_000,
    );

    expect(hits).toHaveLength(1);
    expect(hits[0]?.id).toBe('read-then-egress');
    expect(hits[0]?.evidence).toHaveLength(2);
  });

  it('does not fire when a member fell out of the window', () => {
    const hits = evaluateCombinations(
      policy,
      [
        { serverName: 'fs', toolName: 'read_file', at: 0 },
        { serverName: 'web', toolName: 'fetch', at: 900_000 },
      ],
      900_000,
    );

    expect(hits).toEqual([]);
  });

  it('never lets one call satisfy two members', () => {
    // Otherwise a single tool matching two loose patterns trips a rule that is
    // about two capabilities, all by itself.
    const loose = compilePolicy(
      parsePolicy({
        version: 1,
        combinations: [
          {
            id: 'two-of-a-kind',
            all_of: ['fs__*', 'fs__read_*'],
            window: '10m',
            note: 'needs two separate calls',
          },
        ],
      }),
    );

    expect(
      evaluateCombinations(loose, [{ serverName: 'fs', toolName: 'read_file', at: 1 }], 2),
    ).toEqual([]);
    expect(
      evaluateCombinations(
        loose,
        [
          { serverName: 'fs', toolName: 'read_file', at: 1 },
          { serverName: 'fs', toolName: 'read_dir', at: 2 },
        ],
        3,
      ),
    ).toHaveLength(1);
  });
});

describe('compilePolicy', () => {
  it('lays a per-tool scan override over the defaults without erasing them', () => {
    const policy = compilePolicy(
      parsePolicy({
        version: 1,
        scan: { default: { flag_at: 50 }, tools: { 'web__*': { action: 'block' } } },
      }),
    );
    const settings = policy.scanFor('web', 'fetch');

    expect(settings.action).toBe('block');
    // The override said nothing about `flag_at`, so the default stands. A spread
    // would have erased it, and the field it erases most often is the one
    // stopping the proxy blocking traffic nobody asked it to block.
    expect(settings.flag_at).toBe(50);
  });

  it('falls back to the defaults for a tool no override matches', () => {
    const policy = compilePolicy(parsePolicy({ version: 1 }));

    expect(policy.scanFor('fs', 'read_file').action).toBe('flag');
  });

  it('reports no roles for an unknown caller', () => {
    const policy = compilePolicy(parsePolicy({ version: 1, roles: { alice: ['admin'] } }));

    expect([...policy.rolesFor('bob')]).toEqual([]);
    expect([...policy.rolesFor(undefined)]).toEqual([]);
    expect([...policy.rolesFor('alice')]).toEqual(['admin']);
  });
});
