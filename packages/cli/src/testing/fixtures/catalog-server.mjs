// A minimal MCP server that serves all three catalogues: one tool (`echo`), one
// resource and one resource template, and one prompt. For the tests of a rule that
// has to cover every method a caller can send a server — `servers.<name>.roles` —
// and not only `tools/call`.
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

serveStdio(() => {
  const server = new McpServer({ name: 'catalog-server', version: '1.0.0' });
  server.registerTool(
    'echo',
    { description: 'Echo the given text back.', inputSchema: z.object({ text: z.string() }) },
    async ({ text }) => ({ content: [{ type: 'text', text }] }),
  );
  server.registerResource(
    'note',
    'note://hello',
    { description: 'A note.', mimeType: 'text/plain' },
    async (uri) => ({ contents: [{ uri: uri.href, text: 'the note' }] }),
  );
  server.registerResource(
    'page',
    new ResourceTemplate('page://{name}', { list: undefined }),
    { description: 'A page.', mimeType: 'text/plain' },
    async (uri) => ({ contents: [{ uri: uri.href, text: 'the page' }] }),
  );
  server.registerPrompt(
    'greet',
    { description: 'Greet someone.', argsSchema: z.object({ name: z.string() }) },
    async ({ name }) => ({
      messages: [{ role: 'user', content: { type: 'text', text: `hello ${name}` } }],
    }),
  );
  return server;
});
