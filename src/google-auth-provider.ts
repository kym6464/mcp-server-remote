import { promisify } from 'node:util';

import { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import {
  OAuthClientInformationFull,
  OAuthMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import express, { Request, Response } from 'express';
import {
  createOAuthMetadata,
  mcpAuthRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import { OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { CodeChallengeMethod, OAuth2Client } from 'google-auth-library';
import { OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js';

import type { GenerateAuthUrlOpts } from 'google-auth-library';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';

import { registerCleanupFunction } from './disconnect.js';

// In-memory client store for DCR
export class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  async getClient(clientId: string) {
    return this.clients.get(clientId);
  }

  async registerClient(clientMetadata: OAuthClientInformationFull) {
    this.clients.set(clientMetadata.client_id, clientMetadata);
    return clientMetadata;
  }
}

/**
 * Implements OAuthServerProvider to handle OAuth flows with Google as the identity provider.
 * This provider bridges the gap between MCP's DCR-compliant interface and Google OAuth.
 */
class GoogleOAuthProvider implements OAuthServerProvider {
  private readonly _clientsStore: OAuthRegisteredClientsStore;
  private readonly googleClientId: string;
  private readonly googleClientSecret: string;
  private readonly scope: GenerateAuthUrlOpts['scope'];
  private readonly googleOauthClient: OAuth2Client;

  // Google's OAuth server performs it
  skipLocalPkceValidation = true;

  constructor(
    clientsStore: OAuthRegisteredClientsStore,
    googleClientId: string,
    googleClientSecret: string,
    scope: GenerateAuthUrlOpts['scope']
  ) {
    this._clientsStore = clientsStore;
    this.googleClientId = googleClientId;
    this.googleClientSecret = googleClientSecret;
    this.scope = scope;
    this.googleOauthClient = new OAuth2Client({
      clientId: googleClientId,
      clientSecret: googleClientSecret,
    });
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  async authorize(
    _client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: express.Response
  ): Promise<void> {
    const authUrl = this.googleOauthClient.generateAuthUrl({
      access_type: 'offline',
      redirect_uri: params.redirectUri,
      code_challenge: params.codeChallenge,
      code_challenge_method: CodeChallengeMethod.S256,
      scope: this.scope,
      ...(params.state && { state: params.state }),
    });
    res.redirect(authUrl);
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    _authorizationCode: string
  ): Promise<string> {
    // We don't store challenges locally since Google validates PKCE
    return '';
  }

  async exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string
  ): Promise<OAuthTokens> {
    const { tokens } = await this.googleOauthClient.getToken({
      code: authorizationCode,
      ...(codeVerifier && { codeVerifier }),
      ...(redirectUri && { redirect_uri: redirectUri }),
    });
    // Validate and narrows types
    return OAuthTokensSchema.parse(tokens);
  }

  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[]
  ): Promise<OAuthTokens> {
    // The refreshToken comes from the MCP client (e.g., Claude Desktop) that previously
    // authenticated and is now refreshing their access token. We can't use googleOauthClient
    // because it's a shared instance that doesn't track session-specific tokens, and doesn't offer
    // a stateless API for refresh token exchange (unlike getToken() for authorization codes).
    // Therefore, we call the token endpoint directly instead.
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.googleClientId,
      client_secret: this.googleClientSecret,
      refresh_token: refreshToken,
      ...(scopes?.length && { scopes: scopes.join(' ') }),
    });
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token refresh failed: ${response.status} - ${errorText}`);
    }
    return (await response.json()) as OAuthTokens;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const tokenInfo = await this.googleOauthClient.getTokenInfo(token);
      if (tokenInfo.aud !== this.googleClientId) {
        throw new Error('Token was not issued to this client');
      }
      // Convert milliseconds to seconds
      const expiresAt = Math.floor(tokenInfo.expiry_date / 1000);
      return {
        token,
        clientId: tokenInfo.aud,
        scopes: tokenInfo.scopes || [],
        expiresAt,
      };
    } catch (error) {
      throw new Error(`Invalid or expired token: ${error}`);
    }
  }
}

/**
 * Google OAuth Provider for MCP
 *
 * This provider bridges the gap between MCP's DCR-compliant interface and Google OAuth.
 * MCP clients can dynamically register, but actual authentication goes through Google
 * using pre-registered credentials.
 */
export function setupGoogleAuthServer({
  authServerUrl,
}: {
  authServerUrl: URL;
  mcpServerUrl: URL;
}): OAuthMetadata {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env;
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    throw new Error(
      'Missing required environment variables: GOOGLE_CLIENT_ID and/or GOOGLE_CLIENT_SECRET'
    );
  }

  const clientsStore = new InMemoryClientsStore();

  const googleScopes = [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
  ];

  const provider = new GoogleOAuthProvider(
    clientsStore,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    googleScopes
  );

  const authApp = express();
  authApp.use(express.json());
  authApp.use(express.urlencoded({ extended: true }));

  // Add OAuth routes to the auth server
  authApp.use(mcpAuthRouter({ provider, issuerUrl: authServerUrl, scopesSupported: googleScopes }));

  // Add introspection endpoint for token verification
  authApp.post('/introspect', async (req: Request, res: Response) => {
    try {
      const { token } = req.body;
      if (!token) {
        res.status(400).json({ error: 'Token is required' });
        return;
      }

      const tokenInfo = await provider.verifyAccessToken(token);
      res.json({
        active: true,
        client_id: tokenInfo.clientId,
        scope: tokenInfo.scopes.join(' '),
        exp: tokenInfo.expiresAt,
      });
      return;
    } catch (error) {
      res.status(401).json({
        active: false,
        error: 'Unauthorized',
        error_description: `Invalid token: ${error}`,
      });
    }
  });

  const { port: authPort } = authServerUrl;
  const authServer = authApp.listen(authPort, () => {
    console.log(`Authorization Server listening on port ${authPort}`);
  });
  registerCleanupFunction('Auth Server', promisify(authServer.close.bind(authServer)));

  const oauthMetadata: OAuthMetadata = createOAuthMetadata({
    provider,
    issuerUrl: authServerUrl,
    scopesSupported: googleScopes,
  });

  oauthMetadata.introspection_endpoint = new URL('/introspect', authServerUrl).href;

  return oauthMetadata;
}
