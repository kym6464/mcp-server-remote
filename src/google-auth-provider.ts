import { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import {
  OAuthClientInformationFull,
  OAuthMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import express, { Request, Response } from 'express';
import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  createOAuthMetadata,
  mcpAuthRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import {
  OAuthServerProvider,
  AuthorizationParams,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';

interface GoogleTokenInfo {
  aud: string;
  scope?: string;
  exp?: number;
  expires_in?: number;
}

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
  private readonly googleScopes: string[];
  private readonly authorizationUrl: string;
  private readonly tokenUrl: string;

  constructor(
    clientsStore: OAuthRegisteredClientsStore,
    googleClientId: string,
    googleClientSecret: string,
    googleScopes: string[]
  ) {
    this._clientsStore = clientsStore;
    this.googleClientId = googleClientId;
    this.googleClientSecret = googleClientSecret;
    this.googleScopes = googleScopes;
    this.authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    this.tokenUrl = 'https://oauth2.googleapis.com/token';
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  async authorize(
    _client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: express.Response
  ): Promise<void> {
    const targetUrl = new URL(this.authorizationUrl);
    const searchParams = new URLSearchParams({
      client_id: this.googleClientId,
      response_type: 'code',
      redirect_uri: params.redirectUri,
      code_challenge: params.codeChallenge,
      code_challenge_method: 'S256',
      scope: this.googleScopes.join(' '),
    });
    if (params.state) {
      searchParams.set('state', params.state);
    }
    targetUrl.search = searchParams.toString();
    res.redirect(targetUrl.toString());
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
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authorizationCode,
      ...(codeVerifier && { code_verifier: codeVerifier }),
      ...(redirectUri && { redirect_uri: redirectUri }),
    });
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token exchange failed: ${response.status} - ${errorText}`);
    }
    return (await response.json()) as OAuthTokens;
  }

  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[]
  ): Promise<OAuthTokens> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.googleClientId,
      client_secret: this.googleClientSecret,
      refresh_token: refreshToken,
    });

    if (scopes?.length) {
      params.set('scope', scopes.join(' '));
    }

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token refresh failed: ${response.status} - ${errorText}`);
    }

    return (await response.json()) as OAuthTokens;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    // Verify token with Google's tokeninfo endpoint
    // Note: this is not the recommended way of doing this:
    // https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
    const response = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`
    );

    if (!response.ok) {
      throw new Error('Invalid or expired token');
    }

    const tokenInfo = (await response.json()) as GoogleTokenInfo;

    // Verify the token was issued to our client
    if (tokenInfo.aud !== this.googleClientId) {
      throw new Error('Token was not issued to this client');
    }

    // Calculate expiration timestamp
    // Google returns exp as a string, so we need to convert to number
    let expiresAt: number | undefined;
    if (tokenInfo.exp) {
      expiresAt = Number(tokenInfo.exp);
    } else if (tokenInfo.expires_in) {
      expiresAt = Math.floor(Date.now() / 1000) + Number(tokenInfo.expires_in);
    }

    return {
      token,
      clientId: tokenInfo.aud,
      scopes: tokenInfo.scope ? tokenInfo.scope.split(' ') : [],
      expiresAt,
    };
  }
}

/**
 * Google OAuth Provider for MCP
 *
 * This provider bridges the gap between MCP's DCR-compliant interface and Google OAuth.
 * MCP clients can dynamically register, but actual authentication goes through Google
 * using pre-registered credentials.
 */
export const setupGoogleAuthServer = ({
  authServerUrl,
}: {
  authServerUrl: URL;
  mcpServerUrl: URL;
}): OAuthMetadata => {
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

  // Start the auth server
  const authPort = authServerUrl.port;
  authApp.listen(authPort, () => {
    console.log(`Authorization Server listening on port ${authPort}`);
  });

  const oauthMetadata: OAuthMetadata = createOAuthMetadata({
    provider,
    issuerUrl: authServerUrl,
    scopesSupported: googleScopes,
  });

  oauthMetadata.introspection_endpoint = new URL('/introspect', authServerUrl).href;

  return oauthMetadata;
};
