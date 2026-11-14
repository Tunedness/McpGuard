// A legacy-era-only MCP server: a plain `McpServer` on a stdio transport, which
// never opts into the modern era the way `serveStdio` does. A modern client
// probing it gets no modern answer, so it is the upstream that cannot meet a
// modern downstream.
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const server = new McpServer({ name: 'legacy-only-server', version: '1.0.0' });
server.registerTool(
  'echo',
  { description: 'Echo the given text back.', inputSchema: z.object({ text: z.string() }) },
  async ({ text }) => ({ content: [{ type: 'text', text }] }),
);
await server.connect(new StdioServerTransport());
