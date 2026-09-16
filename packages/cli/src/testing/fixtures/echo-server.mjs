// A minimal MCP server for the wrap end-to-end test. One tool, `echo`, returns
// whatever text it is given — so a test can make the "server" return a poisoned
// result and check that the guard in front of it scanned and rewrote it.
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

serveStdio(() => {
  const server = new McpServer({ name: 'echo-server', version: '1.0.0' });
  server.registerTool(
    'echo',
    { description: 'Echo the given text back.', inputSchema: z.object({ text: z.string() }) },
    async ({ text }) => ({ content: [{ type: 'text', text }] }),
  );
  return server;
});
