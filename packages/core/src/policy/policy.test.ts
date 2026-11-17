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

  it('has no syslog target by default, and gives the facility authpriv', () => {
    const { syslog } = parsePolicy({ version: 1 }).audit;

    expect(syslog).toEqual({ facility: 'authpriv' });
  });

  it('requires a target for checkpoint_to: syslog, and shows the three forms', () => {
    const attempt = () => parsePolicy({ version: 1, audit: { checkpoint_to: 'syslog' } });

    expect(attempt).toThrow(PolicyValidationError);
    expect(attempt).toThrow(/audit\.syslog\.target is required/);
    expect(attempt).toThrow(
      /udp:\/\/127\.0\.0\.1:514.*tcp:\/\/logs\.example\.com:514.*unix:\/\/\/run/,
    );
  });

  it('does not ask for a target when the checkpoint goes elsewhere', () => {
    expect(() => parsePolicy({ version: 1, audit: { checkpoint_to: 'none' } })).not.toThrow();
    expect(() => parsePolicy({ version: 1 })).not.toThrow();
  });

  it.each([
    'udp://logs.example.com:6514',
    'udp://[::1]',
    'tcp://127.0.0.1:601',
    'unix:///run/mcpguard.sock',
  ])('accepts the syslog target %s', (target) => {
    const audit = parsePolicy({
      version: 1,
      audit: { checkpoint_to: 'syslog', syslog: { target } },
    }).audit;

    expect(audit.syslog.target).toBe(target);
  });

  it.each([
    'http://h:514',
    'udp://',
    'udp://h:0',
    'tcp://h:65536',
    'unix:/run/x.sock',
    'unix://rel',
    '/dev/log',
    '',
  ])('rejects the syslog target %j', (target) => {
    expect(() =>
      parsePolicy({ version: 1, audit: { checkpoint_to: 'syslog', syslog: { target } } }),
    ).toThrow(PolicyValidationError);
  });

  it('rejects a syslog facility and a syslog key it does not know', () => {
    expect(() => parsePolicy({ version: 1, audit: { syslog: { facility: 'kern' } } })).toThrow(
      PolicyValidationError,
    );
    expect(() => parsePolicy({ version: 1, audit: { syslog: { host: 'x' } } })).toThrow(
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

describe('evaluateAccess and servers.<name>.roles', () => {
  const policy = compilePolicy(
    parsePolicy({
      version: 1,
      roles: { alice: ['reader'], bob: ['admin', 'ops'] },
      servers: { fs: { roles: ['admin'] }, db: {}, mail: { roles: [] } },
      tools: [{ match: 'fs__rm', action: 'deny', roles: ['admin'] }],
    }),
  );

  it('refuses a caller who holds none of the listed roles, and names the field', () => {
    const decision = evaluateAccess(policy, 'fs', 'read_file', 'alice');

    expect(decision).toMatchObject({
      action: 'deny',
      matchedRule: 'servers.fs.roles',
      refusedByServer: true,
      roles: ['reader'],
    });
  });

  it('refuses a caller with no identity, and one nobody mapped', () => {
    expect(evaluateAccess(policy, 'fs', 'read_file', undefined).action).toBe('deny');
    expect(evaluateAccess(policy, 'fs', 'read_file', 'carol').refusedByServer).toBe(true);
  });

  it('admits a caller holding any one of the listed roles', () => {
    const decision = evaluateAccess(policy, 'fs', 'read_file', 'bob');

    expect(decision).toMatchObject({ action: 'allow', refusedByServer: false });
  });

  it('lets a tool rule deny a caller the server list admitted', () => {
    const decision = evaluateAccess(policy, 'fs', 'rm', 'bob');

    expect(decision).toMatchObject({
      action: 'deny',
      matchedRule: 'tools[0]',
      refusedByServer: false,
    });
  });

  it('leaves a server with an unset or empty list, and an unlisted one, open to everyone', () => {
    for (const server of ['db', 'mail', 'unlisted']) {
      expect(evaluateAccess(policy, server, 'any', undefined)).toMatchObject({
        action: 'allow',
        refusedByServer: false,
      });
    }
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

describe('evaluateCombinations with overlapping globs', () => {
  const rule = (allOf: string[]) =>
    compilePolicy(
      parsePolicy({
        version: 1,
        combinations: [
          { id: 'overlap', all_of: allOf, window: '10m', note: 'overlapping members' },
        ],
      }),
    );
  const call = (toolName: string, at: number) => ({ serverName: 'echo', toolName, at });

  // Each case is a rule that is satisfiable by *some* assignment of distinct
  // calls to globs, and is fed in both orders: a greedy first-match pairing
  // finds it in only one of them.
  it('finds the pairing when the broad glob is written first', () => {
    const p = rule(['echo__*', 'echo__send*']);
    for (const history of [
      [call('read_file', 1), call('send_http', 2)],
      [call('send_http', 1), call('read_file', 2)],
    ]) {
      const hits = evaluateCombinations(p, history, 3);
      expect(hits).toHaveLength(1);
      // One call per glob, in the order the globs were written.
      expect(hits[0]?.evidence.map((mark) => mark.toolName)).toEqual(['read_file', 'send_http']);
    }
  });

  it('finds the pairing when the broad glob is written last', () => {
    const p = rule(['echo__read*', 'echo__*']);
    for (const history of [
      [call('read_file', 1), call('send_http', 2)],
      [call('send_http', 1), call('read_file', 2)],
    ]) {
      const hits = evaluateCombinations(p, history, 3);
      expect(hits).toHaveLength(1);
      expect(hits[0]?.evidence.map((mark) => mark.toolName)).toEqual(['read_file', 'send_http']);
    }
  });

  it('solves a chain of three overlapping globs', () => {
    // `ab` is the only call `echo__ab*` accepts, `a` or `ab` fit `echo__a*`, and
    // anything fits `echo__*`: first-fit hands the broad glob `ab` and strands the rest.
    const p = rule(['echo__*', 'echo__a*', 'echo__ab*']);
    const history = [call('ab', 1), call('a', 2), call('z', 3)];
    const hits = evaluateCombinations(p, history, 4);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence.map((mark) => mark.toolName)).toEqual(['z', 'a', 'ab']);
  });

  it('still refuses when no assignment of distinct calls exists', () => {
    const p = rule(['echo__*', 'echo__a*', 'echo__ab*']);
    // Two calls cannot fill three members, and `z` matches only the broad glob.
    expect(evaluateCombinations(p, [call('ab', 1), call('z', 2)], 3)).toEqual([]);
    expect(evaluateCombinations(p, [call('z', 1), call('y', 2), call('x', 3)], 4)).toEqual([]);
  });

  it('keeps the first matching call as evidence when nothing overlaps', () => {
    const p = rule(['echo__read*', 'echo__send*']);
    const hits = evaluateCombinations(
      p,
      [call('read_a', 1), call('read_b', 2), call('send_a', 3), call('send_b', 4)],
      5,
    );
    expect(hits[0]?.evidence.map((mark) => mark.toolName)).toEqual(['read_a', 'send_a']);
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

describe('the gateway fields (ADR-011)', () => {
  const sha = 'a'.repeat(64);

  it('default to conservative values, so an old policy is still a complete one', () => {
    const policy = defaultPolicy();
    expect(policy.http).toEqual({
      max_body_bytes: 4_194_304,
      max_upstream_response_bytes: 16_777_216,
      max_inflight: 256,
      allowed_hosts: [],
      allowed_origins: [],
    });
    expect(policy.auth.tokens).toEqual([]);
    expect(policy.session.max_sessions).toBe(1024);
    expect(policy.session.max_upstream_connections).toBe(32);
    expect(policy.session.key).toBe('auto');
  });

  it('read a server upstream as a URL or as a command', () => {
    const policy = parsePolicy({
      version: 1,
      servers: {
        docs: { upstream: { url: 'https://mcp.example.com/mcp' } },
        files: { upstream: { command: 'npx', args: ['-y', 'files-mcp'] } },
        bare: { upstream: { command: 'node' } },
        none: {},
      },
    });
    expect(policy.servers.docs?.upstream).toEqual({ url: 'https://mcp.example.com/mcp' });
    expect(policy.servers.files?.upstream).toEqual({ command: 'npx', args: ['-y', 'files-mcp'] });
    expect(policy.servers.bare?.upstream).toEqual({ command: 'node', args: [] });
    expect(policy.servers.none?.upstream).toBeUndefined();
  });

  it('read a per-server PII switch, and nothing else of the pii block per server', () => {
    const policy = parsePolicy({
      version: 1,
      servers: { crm: { pii: { enabled: true } }, logs: { pii: { enabled: false } }, plain: {} },
    });
    expect(policy.servers.crm?.pii).toEqual({ enabled: true });
    expect(policy.servers.logs?.pii).toEqual({ enabled: false });
    expect(policy.servers.plain?.pii).toBeUndefined();
    for (const pii of [{}, { enabled: 'yes' }, { enabled: true, keep_last: 2 }]) {
      expect(() => parsePolicy({ version: 1, servers: { s: { pii } } })).toThrow(
        PolicyValidationError,
      );
    }
  });

  it.each([
    ['a non-http URL', { url: 'file:///etc/passwd' }],
    ['a URL and a command together', { url: 'https://x.example/mcp', command: 'node' }],
    ['neither', {}],
    ['an unknown key', { url: 'https://x.example/mcp', headers: {} }],
    ['an empty command', { command: '' }],
  ])('refuse an upstream with %s', (_label, upstream) => {
    expect(() => parsePolicy({ version: 1, servers: { s: { upstream } } })).toThrow(
      PolicyValidationError,
    );
  });

  it('keep a token as its hash, and refuse anything that is not one', () => {
    const policy = parsePolicy({
      version: 1,
      auth: { tokens: [{ identity: 'alice', token_sha256: sha }] },
    });
    expect(policy.auth.tokens).toEqual([{ identity: 'alice', token_sha256: sha }]);
    for (const bad of ['secret-token', 'A'.repeat(64), 'a'.repeat(63), '']) {
      expect(() =>
        parsePolicy({ version: 1, auth: { tokens: [{ identity: 'x', token_sha256: bad }] } }),
      ).toThrow(PolicyValidationError);
    }
    expect(() =>
      parsePolicy({ version: 1, auth: { tokens: [{ identity: 'x', token: 'plain' }] } }),
    ).toThrow(PolicyValidationError);
  });

  it('refuse the same token listed twice, and allow one identity several tokens', () => {
    expect(() =>
      parsePolicy({
        version: 1,
        auth: {
          tokens: [
            { identity: 'a', token_sha256: sha },
            { identity: 'b', token_sha256: sha },
          ],
        },
      }),
    ).toThrow(/appears twice/);
    const rotated = parsePolicy({
      version: 1,
      auth: {
        tokens: [
          { identity: 'a', token_sha256: sha },
          { identity: 'a', token_sha256: 'b'.repeat(64) },
        ],
      },
    });
    expect(rotated.auth.tokens).toHaveLength(2);
  });

  it('refuse a limit that is zero or negative', () => {
    for (const http of [{ max_body_bytes: 0 }, { max_inflight: -1 }]) {
      expect(() => parsePolicy({ version: 1, http })).toThrow(PolicyValidationError);
    }
    expect(() => parsePolicy({ version: 1, session: { max_upstream_connections: 0 } })).toThrow(
      PolicyValidationError,
    );
  });
});

describe('pii.profile and pii.recognizers', () => {
  it('default to the base set, the way a policy without them always did', () => {
    const policy = parsePolicy({ version: 1 });

    expect(policy.pii.profile).toBe('default');
    expect(policy.pii.recognizers).toEqual([]);
  });

  it('accept the health profile and any shipped recogniser id', () => {
    const policy = parsePolicy({
      version: 1,
      pii: { profile: 'health', recognizers: ['tckn', 'health_ref', 'icd10', 'atc'] },
    });

    expect(policy.pii.profile).toBe('health');
    expect(policy.pii.recognizers).toEqual(['tckn', 'health_ref', 'icd10', 'atc']);
  });

  it('reject an unknown profile and an unknown recogniser id instead of skipping it', () => {
    // A typo in a regulated tenant's list used to switch a recogniser off in silence.
    expect(() => parsePolicy({ version: 1, pii: { profile: 'hipaa' } })).toThrow(
      PolicyValidationError,
    );
    expect(() => parsePolicy({ version: 1, pii: { recognizers: ['tckm'] } })).toThrow(
      PolicyValidationError,
    );
  });
});

describe('the tier-2 judge block (ADR-012)', () => {
  const on = (judge: Record<string, unknown>) =>
    parsePolicy({ version: 1, judge: { enabled: true, model: 'm', ...judge } });
  const rejection = (judge: Record<string, unknown>): string => {
    try {
      on(judge);
    } catch (error) {
      return (error as Error).message;
    }
    return '';
  };

  it('is off, with the measured defaults, in a policy that says nothing', () => {
    expect(defaultPolicy().judge).toEqual({
      enabled: false,
      adapter: 'openai_chat',
      timeout: 5_000,
      reasoning_effort: 'none',
      max_inflight: 1,
      max_input_bytes: 16_384,
      max_tokens: 32,
      circuit_failures: 5,
      circuit_open_for: 30_000,
      allow_remote: false,
    });
  });

  it('needs an endpoint and a model once enabled', () => {
    expect(rejection({ endpoint: undefined })).toMatch(/judge\.endpoint is required/);
    expect(() =>
      parsePolicy({
        version: 1,
        judge: { enabled: true, endpoint: 'http://127.0.0.1:11434/v1/chat/completions' },
      }),
    ).toThrow(/judge\.model is required/);
  });

  it('accepts a loopback endpoint under any of its three names', () => {
    for (const host of ['127.0.0.1:11434', 'localhost:8080', '[::1]:8080']) {
      expect(on({ endpoint: `http://${host}/v1/chat/completions` }).judge.enabled).toBe(true);
    }
  });

  it('refuses an endpoint that is not this machine, unless allow_remote is set, and then wants https', () => {
    expect(rejection({ endpoint: 'http://10.0.0.5:8080/v1/chat/completions' })).toMatch(
      /not on this machine/,
    );
    expect(rejection({ endpoint: 'https://judge.example.com/v1/chat/completions' })).toMatch(
      /allow_remote/,
    );
    expect(rejection({ endpoint: 'http://judge.example.com/v1', allow_remote: true })).toMatch(
      /must be https/,
    );
    expect(
      on({ endpoint: 'https://judge.example.com/v1', allow_remote: true }).judge.allow_remote,
    ).toBe(true);
  });

  it('is not fooled by a loopback name that is only a prefix or a userinfo', () => {
    expect(rejection({ endpoint: 'http://localhost.evil.example/v1' })).toMatch(
      /not on this machine/,
    );
    expect(rejection({ endpoint: 'http://127.0.0.1@evil.example/v1' })).toMatch(
      /credentials|not on this machine/,
    );
  });

  it('refuses credentials in the endpoint', () => {
    expect(rejection({ endpoint: 'http://user:pw@127.0.0.1:8080/v1' })).toMatch(/credentials/);
  });

  it('takes a reasoning effort from the OpenAI set and a sane token budget, and refuses the rest', () => {
    const base = { endpoint: 'http://127.0.0.1:1/v1' };
    expect(on({ ...base, reasoning_effort: 'none', max_tokens: 512 }).judge).toMatchObject({
      reasoning_effort: 'none',
      max_tokens: 512,
    });
    expect(on({ ...base, reasoning_effort: 'omit' }).judge.reasoning_effort).toBe('omit');
    expect(rejection({ ...base, reasoning_effort: 'extreme' })).not.toBe('');
    expect(rejection({ ...base, max_tokens: 4 })).not.toBe('');
    expect(rejection({ ...base, max_tokens: 100_000 })).not.toBe('');
  });

  it('refuses a zero timeout, an unknown adapter and a misspelled key', () => {
    expect(rejection({ endpoint: 'http://127.0.0.1:1/v1', timeout: 0 })).toMatch(/at least 1ms/);
    expect(rejection({ endpoint: 'http://127.0.0.1:1/v1', adapter: 'onnx' })).not.toBe('');
    expect(rejection({ endpoint: 'http://127.0.0.1:1/v1', timeuot: '1s' })).not.toBe('');
  });

  it('reads durations as a person writes them', () => {
    const policy = on({
      endpoint: 'http://127.0.0.1:1/v1',
      timeout: '2s',
      circuit_open_for: '1m',
      band_from: 25,
    });
    expect(policy.judge).toMatchObject({ timeout: 2_000, circuit_open_for: 60_000, band_from: 25 });
  });
});
