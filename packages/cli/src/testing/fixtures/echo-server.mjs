// A minimal MCP server for the wrap end-to-end test. One tool, `echo`, returns
// whatever text it is given — so a test can make the "server" return a poisoned
// result and check that the guard in front of it scanned and rewrote it. Two
// more tools, `read_file` and `send_http`, are the read-then-send pair the
// combination rules are written about; they do nothing but answer. The last,
// `show_capabilities`, returns the client capabilities the server was told, in
// whichever era the connection is in, so a test can compare what a client declared
// with what reached the server behind a proxy.
import { CLIENT_CAPABILITIES_META_KEY, McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

serveStdio(() => {
  const server = new McpServer({ name: 'echo-server', version: '1.0.0' });
  server.registerTool(
    'echo',
    { description: 'Echo the given text back.', inputSchema: z.object({ text: z.string() }) },
    async ({ text }) => ({ content: [{ type: 'text', text }] }),
  );
  server.registerTool(
    'read_file',
    { description: 'Read a file.', inputSchema: z.object({ path: z.string() }) },
    async ({ path }) => ({ content: [{ type: 'text', text: `contents of ${path}` }] }),
  );
  server.registerTool(
    'send_http',
    { description: 'Send a request.', inputSchema: z.object({ url: z.string() }) },
    async ({ url }) => ({ content: [{ type: 'text', text: `sent to ${url}` }] }),
  );
  server.registerTool(
    'show_capabilities',
    {
      description: 'Report the client capabilities this server was given.',
      inputSchema: z.object({}),
    },
    async (_args, ctx) => {
      // Modern: on the request's own envelope. Legacy: what `initialize` declared.
      const declared =
        ctx.mcpReq.envelope?.[CLIENT_CAPABILITIES_META_KEY] ??
        server.server.getClientCapabilities() ??
        {};
      return { content: [{ type: 'text', text: JSON.stringify(declared) }] };
    },
  );
  return server;
});
