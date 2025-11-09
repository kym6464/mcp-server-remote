# mcp-server-remote

The goal of this project is to create a Remote MCP Server that uses Google as the identity provider.

## Approach

Because Google doesn't support Dynamic Client Registration (DCR), we need to bridge the gap by presenting a DCR-compliant interface to MCP clients while using our pre-registered Google OAuth client credentials. This approach was inspired by [FastMCP's OAuthProxy](https://gofastmcp.com/servers/auth/authentication#oauthproxy).

## History

This code was initialized from [simpleStatelessStreamableHttp.ts](https://github.com/modelcontextprotocol/typescript-sdk/blob/2da89dbfc5f61d92bfc3ef6663d8886911bd4666/src/examples/server/simpleStatelessStreamableHttp.ts) example from the MCP TypeScript SDK.
