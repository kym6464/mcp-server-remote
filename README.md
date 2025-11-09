# mcp-server-remote

The goal of this project is to create a Remote MCP Server that uses Google as the identity provider.

## Code Structure

- [index.ts](src/index.ts) - Starts the MCP and Authorization servers
- [google-auth-provider.ts](src/google-auth-provider.ts) - Handles authentication via Google OAuth
- [disconnect.ts](src/disconnect.ts) - Supports [graceful shutdown](#graceful-shutdown)
- [get-mcp-server.ts](src/get-mcp-server.ts) - Defines the MCP tools, resources, etc.

## Testing

1. Start the server via `npm run dev`
2. Start the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) via `npx @modelcontextprotocol/inspector` and set the following options in the left pane:
   - Transport Type: Streamable HTTP
   - URL: http://localhost:3000/mcp
   - Connection Type: Direct
3. To test authentication, do _not_ click the Connect button. Instead,
   - click Open Auth Settings button
   - in the OAuth Authentication card, click Guided Token Refresh
   - click through using the Continue button
4. To test the MCP server, click the Connect button.

## Authorization Approach

Because Google doesn't support Dynamic Client Registration (DCR), we need to bridge the gap by presenting a DCR-compliant interface to MCP clients while using our pre-registered Google OAuth client credentials. This approach was inspired by [FastMCP's OAuthProxy](https://gofastmcp.com/servers/auth/authentication#oauthproxy).

## Graceful Shutdown

The [disconnect module](./src/disconnect.ts) acts as a central registry where other modules can register their cleanup methods. This is useful for modules that create stateful resources (e.g. database connections, HTTP servers) that need to be gracefully cleaned up before Node.js exits.

Without a central registry, we'd need to:

- Keep track of all stateful resources
- Remember to call cleanup on each one
- Handle errors from each cleanup separately
- Call [process.exit](https://nodejs.org/api/process.html#processexitcode) which is not recommended

With this module, we only need to call a single `disconnect()` function and everything gets shut down gracefully.

## History

This code was initialized from [simpleStatelessStreamableHttp.ts](https://github.com/modelcontextprotocol/typescript-sdk/blob/2da89dbfc5f61d92bfc3ef6663d8886911bd4666/src/examples/server/simpleStatelessStreamableHttp.ts) example from the MCP TypeScript SDK.
