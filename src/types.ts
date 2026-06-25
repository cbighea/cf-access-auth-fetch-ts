export interface ClientMetadata {
  clientId: string;
  clientSecret?: string;
  clientIdIssuedAt?: number;
  clientSecretExpiresAt?: number;
  redirectUris?: string[];
  registeredAt?: number;
  raw?: unknown;
}

export interface TokenRecord {
  resourceURL: string;
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresAt?: number;
  scope?: string;
  issuer: string;
  client?: ClientMetadata;
  dynamicClientRegisteredAt?: number;
  raw?: unknown;
}

export interface TokenStore {
  load(resourceURL: string): Promise<TokenRecord | undefined>;
  save(record: TokenRecord): Promise<void>;
  delete(resourceURL: string): Promise<void>;
}

export interface ResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  bearer_methods_supported?: string[];
  scopes_supported?: string[];
  [key: string]: unknown;
}

export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  code_challenge_methods_supported?: string[];
  grant_types_supported?: string[];
  response_types_supported?: string[];
  [key: string]: unknown;
}

export interface ResolvedMetadata {
  resource: ResourceMetadata;
  authorizationServer: AuthorizationServerMetadata;
}

export interface StaticClientConfig {
  clientId: string;
  clientSecret?: string;
}

export interface LoginOptions {
  scopes?: string[];
  redirectURI?: string;
  wwwAuthenticate?: string | string[] | null;
}

export interface AuthManagerOptions {
  store?: TokenStore;
  fetch?: typeof fetch;
  tokenSkewSeconds?: number;
  allowInsecureHTTP?: boolean;
  staticClient?:
    | StaticClientConfig
    | ((issuer: string, resourceURL: string) => StaticClientConfig | undefined);
  openBrowser?: (url: string) => Promise<void> | void;
  authorizationCodeProvider?: (
    authorizationURL: URL,
    redirectURI: string,
  ) => Promise<string> | string;
  clock?: () => number;
  defaultScopes?: string[];
  clientName?: string;
}

export interface AuthChallenge {
  scheme: string;
  params: Record<string, string>;
}
