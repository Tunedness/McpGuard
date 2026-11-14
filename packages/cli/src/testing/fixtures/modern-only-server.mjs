// A modern-era-only MCP server: `serveStdio` told to refuse the 2025 opening. A
// legacy client in front of `wrap` makes `wrap` open a legacy connection to
// this, which it refuses, so it is the upstream that cannot meet a legacy
// downstream.
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

serveStdio(
  () => {
    const server = new McpServer({ name: 'modern-only-server', version: '1.0.0' });
    server.registerTool(
      'echo',
      { description: 'Echo the given text back.', inputSchema: z.object({ text: z.string() }) },
      async ({ text }) => ({ content: [{ type: 'text', text }] }),
    );
    return server;
  },
  { legacy: 'reject' },
);
