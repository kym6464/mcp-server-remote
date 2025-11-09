# mcp-server-remote

The goal of this project is to create a Remote MCP Server that uses Google as the identity provider.

## Getting Started

1. The first step is to acquire an OAuth Client ID and Client Secret by following [this guide](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred). The following Authorized redirect URIs are recommended:

   - http://localhost:6274/oauth/callback/debug - Used by the MCP Inspector authorization flow described in the [testing section](#testing) below
   - http://localhost:6274/oauth/callback - Used by the MCP Inspector
   - https://developers.google.com/oauthplayground - Used by Google's [OAuth 2.0 Playground](https://developers.google.com/oauthplayground/) if you [use your own credentials](https://storage.googleapis.com/kamal-screenshots/ed8f07ba6269c7622202c599fce6807f.jpg).

2. Once you have your Client ID and Client Secret, copy [src/.env.example](src/.env.example) to `src/.env.local` and replace the fake values.

3. Run `npm install` followed by `npm run dev`. You should see the following output in your terminal:

   ```
   Authorization Server listening on port 3001
   MCP Streamable HTTP Server listening on port 3000
   ```

4. Follow the [testing section](#testing) below to test your MCP server.

<details>
<summary>(OPTIONAL) setup instructions for [Claude Code](https://code.claude.com/docs) users</summary>

1. The [block-env-files hook](.claude/hooks/block-env-files.sh) requires that you have [jq](https://jqlang.org/download/) installed on your system.

2. [CLAUDE.md](./CLAUDE.md) expects that you have the https://github.com/modelcontextprotocol/typescript-sdk cloned to `../mcp-typescript-sdk`. This makes it easier for Claude to reference the SDK source code without having to dig through node_modules.

3. Create `.claude/settings.local.json` based on the following:

   ```jsonc
   {
     "permissions": {
       "additionalDirectories": [
         "/path/to/mcp-typescript-sdk" // TODO
       ]
     },
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Read",
           "hooks": [
             {
               "type": "command",
               "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/block-env-files.sh"
             }
           ]
         }
       ]
     }
   }
   ```

</details>

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

## Development

### Code Structure

- [index.ts](src/index.ts) - Starts the MCP and Authorization servers
- [google-auth-provider.ts](src/google-auth-provider.ts) - Handles authentication via Google OAuth
- [disconnect.ts](src/disconnect.ts) - Supports [graceful shutdown](#graceful-shutdown)
- [get-mcp-server.ts](src/get-mcp-server.ts) - Defines the MCP tools, resources, etc.

### Authorization Approach

Because Google doesn't support Dynamic Client Registration (DCR), we need to bridge the gap by presenting a DCR-compliant interface to MCP clients while using our pre-registered Google OAuth client credentials. This approach was inspired by [FastMCP's OAuthProxy](https://gofastmcp.com/servers/auth/authentication#oauthproxy).

### Graceful Shutdown

The [disconnect module](./src/disconnect.ts) acts as a central registry where other modules can register their cleanup methods. This is useful for modules that create stateful resources (e.g. database connections, HTTP servers) that need to be gracefully cleaned up before Node.js exits.

Without a central registry, we'd need to:

- Keep track of all stateful resources
- Remember to call cleanup on each one
- Handle errors from each cleanup separately
- Call [process.exit](https://nodejs.org/api/process.html#processexitcode) which is not recommended

With this module, we only need to call a single `disconnect()` function and everything gets shut down gracefully.

## History

This code was initialized from [simpleStatelessStreamableHttp.ts](https://github.com/modelcontextprotocol/typescript-sdk/blob/2da89dbfc5f61d92bfc3ef6663d8886911bd4666/src/examples/server/simpleStatelessStreamableHttp.ts) example from the MCP TypeScript SDK.
