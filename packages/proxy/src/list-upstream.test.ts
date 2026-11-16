import { afterEach, describe, expect, it } from 'vitest';
import { listUpstreamTools } from './list-tools.js';
import { startUpstream, type TestUpstream } from './testing/upstream-server.js';

/**
 * `listUpstreamTools` is what `mcpguard lock --server` reads a policy's upstream
 * with: the gateway's own connection path, in whichever era the server speaks.
 */

const open: TestUpstream[] = [];
afterEach(async () => {
  await Promise.allSettled(open.splice(0).map((upstream) => upstream.close()));
});

const namesOf = (tools: unknown[]): string[] =>
  tools.map((tool) => (tool as { name: string }).name).sort();

describe('listUpstreamTools', () => {
  it.each(['modern', 'legacy', 'both'] as const)(
    'reads the whole tool list of a %s upstream, and leaves no session open',
    async (era) => {
      const upstream = await startUpstream(era);
      open.push(upstream);
      const tools = await listUpstreamTools({
        target: { url: upstream.url },
        clientName: 'mcpguard-lock',
      });
      expect(namesOf(tools)).toContain('echo');
      // The upstream drops the session after it has answered the DELETE.
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(upstream.sessions()).toBe(0);
    },
  );

  it('fails, rather than answering with nothing, when the upstream is not there', async () => {
    const upstream = await startUpstream('both');
    const url = upstream.url;
    await upstream.close();
    await expect(
      listUpstreamTools({ target: { url }, clientName: 'mcpguard-lock' }),
    ).rejects.toThrow();
  });

  it('holds the response ceiling the gateway holds', async () => {
    const upstream = await startUpstream('both');
    open.push(upstream);
    await expect(
      listUpstreamTools({
        target: { url: upstream.url },
        clientName: 'mcpguard-lock',
        maxResponseBytes: 16,
      }),
    ).rejects.toThrow();
  });
});
