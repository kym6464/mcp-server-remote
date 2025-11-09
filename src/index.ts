import { promisify } from 'node:util';

import cors from 'cors';
import express, { Request, Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';

import type { OAuthMetadata } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';

import { setupGoogleAuthServer } from './google-auth-provider.js';
import { disconnect, registerCleanupFunction } from './disconnect.js';

const MCP_PORT = Number(process.env.MCP_PORT) || 3000;
const AUTH_PORT = Number(process.env.MCP_AUTH_PORT) || 3001;
const DISABLE_AUTH = process.env.DISABLE_AUTH === 'true';

function getMcpServer() {
  const server = new McpServer({
    name: 'stateless-streamable-http-server',
    version: '1.0.0',
  });

  // Register a simple prompt
  server.registerPrompt(
    'greeting-template',
    {
      title: 'Greeting Template',
      description: 'A simple greeting prompt template',
      argsSchema: {
        name: z.string().describe('Name to include in greeting'),
      },
    },
    async ({ name }) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Please greet ${name} in a friendly manner.`,
            },
          },
        ],
      };
    }
  );

  // Register a simple tool
  server.registerTool(
    'add',
    {
      title: 'Add Two Numbers',
      description: 'Adds two numbers together and returns the result',
      inputSchema: {
        a: z.number().describe('First number'),
        b: z.number().describe('Second number'),
      },
    },
    async ({ a, b }) => {
      const result = a + b;
      return {
        content: [
          {
            type: 'text',
            text: `${a} + ${b} = ${result}`,
          },
        ],
      };
    }
  );

  // Create a simple resource at a fixed URI
  server.registerResource(
    'greeting-resource',
    'https://example.com/greetings/default',
    {
      title: 'Greeting Resource',
      description: 'A simple greeting resource',
      mimeType: 'text/plain',
    },
    async () => {
      return {
        contents: [
          {
            uri: 'https://example.com/greetings/default',
            text: 'Hello, world!',
          },
        ],
      };
    }
  );

  return server;
}

const app = express();
app.use(express.json());

// Support browser-based clients
app.use(cors({ origin: '*', exposedHeaders: ['Mcp-Session-Id'] }));

// Set up OAuth if enabled
let authMiddleware = null;
if (!DISABLE_AUTH) {
  // Create auth middleware for MCP endpoints
  const mcpServerUrl = new URL(`http://localhost:${MCP_PORT}/mcp`);
  const authServerUrl = new URL(`http://localhost:${AUTH_PORT}`);

  const oauthMetadata: OAuthMetadata = setupGoogleAuthServer({
    authServerUrl,
    mcpServerUrl,
  });

  const tokenVerifier: OAuthTokenVerifier = {
    async verifyAccessToken(token) {
      const endpoint = oauthMetadata.introspection_endpoint;
      if (!endpoint) {
        throw new Error('No token verification endpoint available in metadata');
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: token }).toString(),
      });
      if (!response.ok) {
        throw new Error(`Invalid or expired token: ${await response.text()}`);
      }

      const data = (await response.json()) as { [key: string]: any };
      return {
        token,
        clientId: data.client_id,
        scopes: data.scope ? data.scope.split(' ') : [],
        expiresAt: data.exp,
      };
    },
  };

  // Add metadata routes to the main MCP server
  app.use(
    mcpAuthMetadataRouter({
      oauthMetadata,
      resourceServerUrl: mcpServerUrl,
    })
  );

  authMiddleware = requireBearerAuth({
    verifier: tokenVerifier,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
  });
}

// MCP POST endpoint with optional auth
const mcpPostHandler = async (req: Request, res: Response) => {
  if (!DISABLE_AUTH && req.auth) {
    console.log('Authenticated user:', req.auth);
  }

  const server = getMcpServer();
  try {
    const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
      // Session IDs are not useful in stateless mode
      sessionIdGenerator: undefined,
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    res.on('close', () => {
      console.log('Request closed');
      transport.close();
      server.close();
    });
  } catch (error) {
    console.error('Failed to handle MCP request:', error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32603, message: 'Internal server error' },
        id: null,
      });
    }
  }
};

if (authMiddleware) {
  app.post('/mcp', authMiddleware, mcpPostHandler);
} else {
  app.post('/mcp', mcpPostHandler);
}

// GET requests are not supported in stateless mode
const mcpGetHandler = async (_req: Request, res: Response) => {
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed.' },
      id: null,
    })
  );
};

// DELETE requests are not supported in stateless mode
const mcpDeleteHandler = async (_req: Request, res: Response) => {
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed.' },
      id: null,
    })
  );
};

// Set up GET route with conditional auth middleware
if (authMiddleware) {
  app.get('/mcp', authMiddleware, mcpGetHandler);
} else {
  app.get('/mcp', mcpGetHandler);
}

// Set up DELETE route with conditional auth middleware
if (authMiddleware) {
  app.delete('/mcp', authMiddleware, mcpDeleteHandler);
} else {
  app.delete('/mcp', mcpDeleteHandler);
}

const mcpServer = app.listen(MCP_PORT, (error) => {
  if (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
  console.log(`MCP Streamable HTTP Server listening on port ${MCP_PORT}`);
});
registerCleanupFunction('MCP Server', promisify(mcpServer.close.bind(mcpServer)));

process.on('SIGINT', () => {
  console.log('SIGINT received, gracefully shutting down...');
  disconnect().then(() => console.log('Graceful shutdown complete'));
});
