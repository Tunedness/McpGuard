// A stdio MCP server that dies on request, for the tests of what a gateway does when the
// process behind a session goes away. `echo` answers; `crash` answers and then exits.
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

serveStdio(() => {
  const server = new McpServer({ name: 'crash-server', version: '1.0.0' });
  server.registerTool(
    'echo',
    { description: 'Echo the given text back.', inputSchema: z.object({ text: z.string() }) },
    async ({ text }) => ({ content: [{ type: 'text', text }] }),
  );
  server.registerTool(
    'crash',
    { description: 'Answer, then exit the process.', inputSchema: z.object({}) },
    async () => {
      setTimeout(() => process.exit(1), 50);
      return { content: [{ type: 'text', text: 'going down' }] };
    },
  );
  return server;
});
