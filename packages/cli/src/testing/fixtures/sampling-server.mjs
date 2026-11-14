// A legacy-era MCP server that asks the client a question mid-call.
//
// `ask_roots` calls `roots/list` on the client and returns what came back as
// text, so a test can see whether a capability the client declared reached the
// server and whether the server's request reached the client. Like any server
// that follows the spec, it asks only a client that declared `roots`; otherwise
// it says so, which is what a client behind a proxy that dropped the capability
// would see. A plain
// `McpServer` on a stdio transport, because a server-to-client request is a
// legacy-era mechanism (the modern era answers with `input_required` instead).
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const server = new McpServer({ name: 'sampling-server', version: '1.0.0' });
server.registerTool(
  'ask_roots',
  { description: 'List the roots the client exposes.', inputSchema: z.object({}) },
  async () => {
    if (server.server.getClientCapabilities()?.roots === undefined) {
      return {
        content: [{ type: 'text', text: 'the client declared no roots capability' }],
        isError: true,
      };
    }
    try {
      const { roots } = await server.server.listRoots();
      return { content: [{ type: 'text', text: roots.map((root) => root.uri).join(',') }] };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `roots unavailable: ${error.message}` }],
        isError: true,
      };
    }
  },
);
await server.connect(new StdioServerTransport());
