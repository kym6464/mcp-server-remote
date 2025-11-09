import express, { Request, Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import {
  CallToolResult,
  GetPromptResult,
  ReadResourceResult,
} from '@modelcontextprotocol/sdk/types.js';
import cors from 'cors';
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { OAuthMetadata } from '@modelcontextprotocol/sdk/shared/auth.js';
import { checkResourceAllowed } from '@modelcontextprotocol/sdk/shared/auth-utils.js';

import { setupAuthServer } from './demoInMemoryOAuthProvider.js';

// Check for OAuth flag
const useOAuth = process.argv.includes('--oauth');
const strictOAuth = process.argv.includes('--oauth-strict');

const getServer = () => {
  // Create an MCP server with implementation details
  const server = new McpServer(
    {
      name: 'stateless-streamable-http-server',
      version: '1.0.0',
    },
    { capabilities: { logging: {} } }
  );

  // Register a simple prompt
  server.prompt(
    'greeting-template',
    'A simple greeting prompt template',
    {
      name: z.string().describe('Name to include in greeting'),
    },
    async ({ name }): Promise<GetPromptResult> => {
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

  // Register a tool specifically for testing resumability
  server.tool(
    'start-notification-stream',
    'Starts sending periodic notifications for testing resumability',
    {
      interval: z.number().describe('Interval in milliseconds between notifications').default(100),
      count: z.number().describe('Number of notifications to send (0 for 100)').default(10),
    },
    async ({ interval, count }, extra): Promise<CallToolResult> => {
      const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
      let counter = 0;

      while (count === 0 || counter < count) {
        counter++;
        try {
          await server.sendLoggingMessage(
            {
              level: 'info',
              data: `Periodic notification #${counter} at ${new Date().toISOString()}`,
            },
            extra.sessionId
          );
        } catch (error) {
          console.error('Error sending notification:', error);
        }
        // Wait for the specified interval
        await sleep(interval);
      }

      return {
        content: [
          {
            type: 'text',
            text: `Started sending periodic notifications every ${interval}ms`,
          },
        ],
      };
    }
  );

  // Create a simple resource at a fixed URI
  server.resource(
    'greeting-resource',
    'https://example.com/greetings/default',
    { mimeType: 'text/plain' },
    async (): Promise<ReadResourceResult> => {
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
};

const MCP_PORT = process.env.MCP_PORT ? parseInt(process.env.MCP_PORT, 10) : 3000;
const AUTH_PORT = process.env.MCP_AUTH_PORT ? parseInt(process.env.MCP_AUTH_PORT, 10) : 3001;

const app = express();
app.use(express.json());

// Configure CORS to expose Mcp-Session-Id header for browser-based clients
app.use(
  cors({
    origin: '*', // Allow all origins - adjust as needed for production
    exposedHeaders: ['Mcp-Session-Id'],
  })
);

// Set up OAuth if enabled
let authMiddleware = null;
if (useOAuth) {
  // Create auth middleware for MCP endpoints
  const mcpServerUrl = new URL(`http://localhost:${MCP_PORT}/mcp`);
  const authServerUrl = new URL(`http://localhost:${AUTH_PORT}`);

  const oauthMetadata: OAuthMetadata = setupAuthServer({
    authServerUrl,
    mcpServerUrl,
    strictResource: strictOAuth,
  });

  const tokenVerifier = {
    verifyAccessToken: async (token: string) => {
      const endpoint = oauthMetadata.introspection_endpoint;

      if (!endpoint) {
        throw new Error('No token verification endpoint available in metadata');
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          token: token,
        }).toString(),
      });

      if (!response.ok) {
        throw new Error(`Invalid or expired token: ${await response.text()}`);
      }

      const data = (await response.json()) as { [key: string]: any };

      if (strictOAuth) {
        if (!data.aud) {
          throw new Error(`Resource Indicator (RFC8707) missing`);
        }
        if (
          !checkResourceAllowed({ requestedResource: data.aud, configuredResource: mcpServerUrl })
        ) {
          throw new Error(`Expected resource indicator ${mcpServerUrl}, got: ${data.aud}`);
        }
      }

      // Convert the response to AuthInfo format
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
      scopesSupported: ['mcp:tools'],
      resourceName: 'MCP Demo Server',
    })
  );

  authMiddleware = requireBearerAuth({
    verifier: tokenVerifier,
    requiredScopes: [],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
  });
}

// MCP POST endpoint with optional auth
const mcpPostHandler = async (req: Request, res: Response) => {
  if (useOAuth && req.auth) {
    console.log('Authenticated user:', req.auth);
  }

  const server = getServer();
  try {
    const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
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
    console.error('Error handling MCP request:', error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error',
        },
        id: null,
      });
    }
  }
};

// Set up routes with conditional auth middleware
if (useOAuth && authMiddleware) {
  app.post('/mcp', authMiddleware, mcpPostHandler);
} else {
  app.post('/mcp', mcpPostHandler);
}

// Handle GET requests (not supported in stateless mode)
const mcpGetHandler = async (req: Request, res: Response) => {
  if (useOAuth && req.auth) {
    console.log('Authenticated GET request from user:', req.auth);
  }
  console.log('Received GET MCP request');
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: '2.0',
      error: {
        code: -32000,
        message: 'Method not allowed.',
      },
      id: null,
    })
  );
};

// Handle DELETE requests (not supported in stateless mode)
const mcpDeleteHandler = async (req: Request, res: Response) => {
  if (useOAuth && req.auth) {
    console.log('Authenticated DELETE request from user:', req.auth);
  }
  console.log('Received DELETE MCP request');
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: '2.0',
      error: {
        code: -32000,
        message: 'Method not allowed.',
      },
      id: null,
    })
  );
};

// Set up GET route with conditional auth middleware
if (useOAuth && authMiddleware) {
  app.get('/mcp', authMiddleware, mcpGetHandler);
} else {
  app.get('/mcp', mcpGetHandler);
}

// Set up DELETE route with conditional auth middleware
if (useOAuth && authMiddleware) {
  app.delete('/mcp', authMiddleware, mcpDeleteHandler);
} else {
  app.delete('/mcp', mcpDeleteHandler);
}

// Start the server
app.listen(MCP_PORT, (error) => {
  if (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
  console.log(`MCP Stateless Streamable HTTP Server listening on port ${MCP_PORT}`);
});

// Handle server shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  process.exit(0);
});
