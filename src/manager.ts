import type {
  AuthManagerOptions,
  AuthorizationServerMetadata,
  ClientMetadata,
  LoginOptions,
  ResourceMetadata,
  ResolvedMetadata,
  StaticClientConfig,
  TokenRecord,
  TokenStore,
} from "./types.js";
import { InteractionRequiredError, MetadataError, OAuthError } from "./errors.js";
import { FileTokenStore } from "./stores.js";
import { openBrowser } from "./browser.js";
import { createLoopbackServer } from "./loopback.js";
import { generatePKCE, randomString } from "./pkce.js";
import { parseWWWAuthenticate } from "./www-authenticate.js";
import {
  authorizationServerMetadataURL,
  cloudflareAuthorizationServerMetadataURL,
  isLoopbackHost,
  normalizeResourceURL,
  protectedResourceMetadataURL,
  resourceOrigin,
} from "./urls.js";
import { cacheSeconds, isMetadataFetchFailure, safeJSON } from "./utils.js";

interface CachedValue<T> {
  value: T;
  expiresAt: number;
}

export class AuthManager {
  readonly store: TokenStore;
  private readonly fetchImpl: typeof fetch;
  private readonly tokenSkewSeconds: number;
  private readonly allowInsecureHTTP: boolean;
  private readonly staticClient?: AuthManagerOptions["staticClient"];
  private readonly openBrowser?: AuthManagerOptions["openBrowser"];
  private readonly authorizationCodeProvider?: AuthManagerOptions["authorizationCodeProvider"];
  private readonly clock: () => number;
  private readonly defaultScopes: string[];
  private readonly clientName: string;
  private readonly resourceMetadataCache = new Map<string, CachedValue<ResourceMetadata>>();
  private readonly serverMetadataCache = new Map<string, CachedValue<AuthorizationServerMetadata>>();

  constructor(options: AuthManagerOptions = {}) {
    this.store = options.store ?? new FileTokenStore();
    this.fetchImpl = options.fetch ?? fetch;
    this.tokenSkewSeconds = options.tokenSkewSeconds ?? 60;
    this.allowInsecureHTTP = options.allowInsecureHTTP ?? false;
    this.staticClient = options.staticClient;
    this.openBrowser = options.openBrowser;
    this.authorizationCodeProvider = options.authorizationCodeProvider;
    this.clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
    this.defaultScopes = options.defaultScopes ?? [];
    this.clientName = options.clientName ?? "cf-access-auth-fetch-ts";
  }

  async login(resourceURL: string, options: LoginOptions = {}): Promise<TokenRecord> {
    const resource = normalizeResourceURL(resourceURL);
    this.assertSecureURL(resource);
    const resolved = await this.metadata(resource, { wwwAuthenticate: options.wwwAuthenticate });
    const scopes = options.scopes ?? this.defaultScopes;
    const state = randomString();
    const loopback =
      options.redirectURI || this.authorizationCodeProvider
        ? undefined
        : await createLoopbackServer(state);
    const redirectURI = options.redirectURI ?? loopback?.redirectURI ?? "http://127.0.0.1/callback";

    try {
      const client = await this.ensureClient(resolved.authorizationServer, resource, redirectURI);
      const pkce = generatePKCE();
      const authorizationURL = this.authorizationURL(
        resolved.authorizationServer,
        client,
        resource,
        redirectURI,
        state,
        pkce.challenge,
        scopes,
      );

      const codePromise = this.authorizationCodeProvider
        ? Promise.resolve(this.authorizationCodeProvider(authorizationURL, redirectURI))
        : loopback?.waitForCode;

      if (!codePromise) {
        throw new OAuthError("No authorization code receiver is configured");
      }

      await (this.openBrowser ?? openBrowser)(authorizationURL.toString());
      const code = await codePromise;
      const tokenResponse = await this.exchangeCode(
        resolved.authorizationServer,
        client,
        resource,
        redirectURI,
        code,
        pkce.verifier,
      );
      const record = this.tokenRecord(resource, resolved.authorizationServer, client, tokenResponse);
      await this.store.save(record);
      return record;
    } finally {
      await loopback?.close();
    }
  }

  async logout(resourceURL: string): Promise<void> {
    const resource = normalizeResourceURL(resourceURL);
    this.assertSecureURL(resource);
    await this.store.delete(resource);
  }

  async getToken(resourceURL: string): Promise<string | undefined> {
    const resource = normalizeResourceURL(resourceURL);
    this.assertSecureURL(resource);
    const record = await this.store.load(resource);
    if (!record) {
      return undefined;
    }
    if (!record.expiresAt || record.expiresAt > this.clock() + this.tokenSkewSeconds) {
      return record.accessToken;
    }
    const refreshed = await this.refresh(resource);
    return refreshed.accessToken;
  }

  async refresh(resourceURL: string): Promise<TokenRecord> {
    const resource = normalizeResourceURL(resourceURL);
    this.assertSecureURL(resource);
    const record = await this.store.load(resource);
    if (!record?.refreshToken) {
      await this.store.delete(resource);
      throw new InteractionRequiredError("No refresh token is available", {
        error: "interaction_required",
      });
    }

    const resolved = await this.metadata(resource);
    const client = this.clientFromRecordOrStatic(record, resolved.authorizationServer, resource);
    if (!client) {
      await this.store.delete(resource);
      throw new InteractionRequiredError("No OAuth client metadata is available", {
        error: "interaction_required",
      });
    }

    try {
      const tokenResponse = await this.postForm(resolved.authorizationServer.token_endpoint, {
        grant_type: "refresh_token",
        refresh_token: record.refreshToken,
        client_id: client.clientId,
        client_secret: client.clientSecret,
        resource,
      });
      const refreshed = this.tokenRecord(resource, resolved.authorizationServer, client, {
        ...tokenResponse,
        refresh_token: tokenResponse.refresh_token ?? record.refreshToken,
      });
      await this.store.save(refreshed);
      return refreshed;
    } catch (error) {
      if (error instanceof OAuthError && error.error === "invalid_grant") {
        await this.store.delete(resource);
        throw new InteractionRequiredError("Refresh token is invalid or expired", {
          error: "invalid_grant",
          status: error.status,
        });
      }
      throw error;
    }
  }

  async metadata(
    resourceURL: string,
    options: { wwwAuthenticate?: string | string[] | null } = {},
  ): Promise<ResolvedMetadata> {
    const resource = normalizeResourceURL(resourceURL);
    this.assertSecureURL(resource);

    const resourceMetadataURL = this.resourceMetadataURLFromChallenge(options.wwwAuthenticate);
    if (resourceMetadataURL) {
      this.assertSecureURL(resourceMetadataURL);
      const metadata = await this.fetchResourceMetadata(resourceMetadataURL, resource);
      return {
        resource: metadata,
        authorizationServer: await this.authorizationServerForResource(metadata, resource),
      };
    }

    try {
      const metadata = await this.fetchResourceMetadata(
        protectedResourceMetadataURL(resource),
        resource,
      );
      return {
        resource: metadata,
        authorizationServer: await this.authorizationServerForResource(metadata, resource),
      };
    } catch (error) {
      if (!(error instanceof MetadataError) || !isMetadataFetchFailure(error)) {
        throw error;
      }
    }

    const serverMetadata = await this.fetchAuthorizationServerMetadata(
      cloudflareAuthorizationServerMetadataURL(resource),
      resourceOrigin(resource),
    );
    return {
      resource: {
        resource,
        authorization_servers: [serverMetadata.issuer],
      },
      authorizationServer: serverMetadata,
    };
  }

  private async authorizationServerForResource(
    metadata: ResourceMetadata,
    resourceURL: string,
  ): Promise<AuthorizationServerMetadata> {
    const issuer = metadata.authorization_servers?.[0];
    if (!issuer) {
      return this.fetchAuthorizationServerMetadata(
        cloudflareAuthorizationServerMetadataURL(resourceURL),
        resourceOrigin(resourceURL),
      );
    }
    this.assertIssuerURL(issuer);
    return this.fetchAuthorizationServerMetadata(authorizationServerMetadataURL(issuer), issuer);
  }

  private resourceMetadataURLFromChallenge(
    wwwAuthenticate?: string | string[] | null,
  ): string | undefined {
    if (!wwwAuthenticate) {
      return undefined;
    }
    for (const challenge of parseWWWAuthenticate(wwwAuthenticate)) {
      if (challenge.scheme !== "bearer") {
        continue;
      }
      const resourceMetadata = challenge.params.resource_metadata;
      if (resourceMetadata) {
        return resourceMetadata;
      }
    }
    return undefined;
  }

  private async fetchResourceMetadata(url: string, resourceURL: string): Promise<ResourceMetadata> {
    const metadata = await this.fetchJSON<ResourceMetadata>(url, this.resourceMetadataCache);
    if (!metadata.resource) {
      throw new MetadataError("Protected resource metadata is missing resource");
    }
    if (metadata.resource !== resourceURL) {
      throw new MetadataError(
        `Protected resource metadata resource mismatch: expected ${resourceURL}`,
      );
    }
    if (
      Array.isArray(metadata.bearer_methods_supported) &&
      !metadata.bearer_methods_supported.some((method) => method.toLowerCase() === "header")
    ) {
      throw new MetadataError(
        "Protected resource does not support bearer tokens in the Authorization header",
      );
    }
    return metadata;
  }

  private async fetchAuthorizationServerMetadata(
    url: string,
    expectedIssuer: string,
  ): Promise<AuthorizationServerMetadata> {
    const metadata = await this.fetchJSON<AuthorizationServerMetadata>(url, this.serverMetadataCache);
    if (!metadata.issuer) {
      throw new MetadataError("Authorization server metadata is missing issuer");
    }
    this.assertIssuerURL(metadata.issuer);
    if (metadata.issuer !== expectedIssuer) {
      throw new MetadataError(
        `Authorization server metadata issuer mismatch: expected ${expectedIssuer}`,
      );
    }
    if (!metadata.authorization_endpoint) {
      throw new MetadataError("Authorization server metadata is missing authorization_endpoint");
    }
    if (!metadata.token_endpoint) {
      throw new MetadataError("Authorization server metadata is missing token_endpoint");
    }
    this.assertEndpointURL(metadata.authorization_endpoint, "authorization_endpoint");
    this.assertEndpointURL(metadata.token_endpoint, "token_endpoint");
    if (metadata.registration_endpoint) {
      this.assertEndpointURL(metadata.registration_endpoint, "registration_endpoint");
    }
    const methods = metadata.code_challenge_methods_supported;
    if (Array.isArray(methods) && !methods.includes("S256")) {
      throw new MetadataError("Authorization server does not advertise PKCE S256 support");
    }
    return metadata;
  }

  private async fetchJSON<T>(url: string, cache: Map<string, CachedValue<T>>): Promise<T> {
    this.assertSecureURL(url);
    const now = this.clock();
    const cached = cache.get(url);
    if (cached && cached.expiresAt > now) {
      return cached.value;
    }

    const response = await this.fetchImpl(url, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new MetadataError(`Metadata request failed with HTTP ${response.status}`);
    }
    const value = (await response.json()) as T;
    cache.set(url, {
      value,
      expiresAt: now + cacheSeconds(response.headers),
    });
    return value;
  }

  private async ensureClient(
    metadata: AuthorizationServerMetadata,
    resourceURL: string,
    redirectURI: string,
  ): Promise<ClientMetadata> {
    const staticClient = this.resolveStaticClient(metadata.issuer, resourceURL);
    if (staticClient) {
      return {
        clientId: staticClient.clientId,
        clientSecret: staticClient.clientSecret,
        redirectUris: [redirectURI],
      };
    }
    const existing = await this.store.load(resourceURL);
    if (existing?.client?.clientId && existing.issuer === metadata.issuer) {
      return existing.client;
    }
    if (!metadata.registration_endpoint) {
      throw new OAuthError(
        "Authorization server does not advertise dynamic client registration and no static client is configured",
      );
    }

    const response = await this.fetchImpl(metadata.registration_endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_name: this.clientName,
        redirect_uris: [redirectURI],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    });
    const body = (await safeJSON(response)) as Record<string, unknown>;
    if (!response.ok || typeof body.client_id !== "string") {
      throw new OAuthError("Dynamic client registration failed", {
        error: typeof body.error === "string" ? body.error : undefined,
        status: response.status,
      });
    }
    const redirectUris = Array.isArray(body.redirect_uris)
      ? body.redirect_uris.filter((value): value is string => typeof value === "string")
      : [];
    return {
      clientId: body.client_id,
      clientSecret: typeof body.client_secret === "string" ? body.client_secret : undefined,
      clientIdIssuedAt:
        typeof body.client_id_issued_at === "number" ? body.client_id_issued_at : undefined,
      clientSecretExpiresAt:
        typeof body.client_secret_expires_at === "number"
          ? body.client_secret_expires_at
          : undefined,
      redirectUris: redirectUris.length > 0 ? redirectUris : [redirectURI],
      registeredAt: this.clock(),
      raw: body,
    };
  }

  private resolveStaticClient(
    issuer: string,
    resourceURL: string,
  ): StaticClientConfig | undefined {
    if (!this.staticClient) {
      return undefined;
    }
    if (typeof this.staticClient === "function") {
      return this.staticClient(issuer, resourceURL);
    }
    return this.staticClient;
  }

  private clientFromRecordOrStatic(
    record: TokenRecord,
    metadata: AuthorizationServerMetadata,
    resourceURL: string,
  ): ClientMetadata | undefined {
    const staticClient = this.resolveStaticClient(metadata.issuer, resourceURL);
    if (staticClient) {
      return { clientId: staticClient.clientId, clientSecret: staticClient.clientSecret };
    }
    return record.client;
  }

  private authorizationURL(
    metadata: AuthorizationServerMetadata,
    client: ClientMetadata,
    resourceURL: string,
    redirectURI: string,
    state: string,
    codeChallenge: string,
    scopes: string[],
  ): URL {
    const url = new URL(metadata.authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", client.clientId);
    url.searchParams.set("redirect_uri", redirectURI);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("resource", resourceURL);
    if (scopes.length > 0) {
      url.searchParams.set("scope", scopes.join(" "));
    }
    return url;
  }

  private async exchangeCode(
    metadata: AuthorizationServerMetadata,
    client: ClientMetadata,
    resourceURL: string,
    redirectURI: string,
    code: string,
    codeVerifier: string,
  ): Promise<Record<string, unknown>> {
    return this.postForm(metadata.token_endpoint, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      code_verifier: codeVerifier,
      client_id: client.clientId,
      client_secret: client.clientSecret,
      resource: resourceURL,
    });
  }

  private async postForm(
    url: string,
    values: Record<string, string | undefined>,
  ): Promise<Record<string, unknown>> {
    this.assertSecureURL(url);
    const form = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
      if (value !== undefined) {
        form.set(key, value);
      }
    }
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: form,
    });
    const body = (await safeJSON(response)) as Record<string, unknown>;
    if (!response.ok) {
      throw new OAuthError("OAuth token request failed", {
        error: typeof body.error === "string" ? body.error : undefined,
        status: response.status,
      });
    }
    return body;
  }

  private tokenRecord(
    resourceURL: string,
    metadata: AuthorizationServerMetadata,
    client: ClientMetadata,
    tokenResponse: Record<string, unknown>,
  ): TokenRecord {
    if (typeof tokenResponse.access_token !== "string") {
      throw new OAuthError("Token response is missing access_token");
    }
    if (typeof tokenResponse.token_type !== "string" || tokenResponse.token_type.length === 0) {
      throw new OAuthError("Token response is missing token_type");
    }
    const tokenType = tokenResponse.token_type;
    if (tokenType.toLowerCase() !== "bearer") {
      throw new OAuthError("Token response returned unsupported token_type", {
        error: "unsupported_token_type",
      });
    }
    const expiresIn =
      typeof tokenResponse.expires_in === "number" ? tokenResponse.expires_in : undefined;
    return {
      resourceURL,
      accessToken: tokenResponse.access_token,
      refreshToken:
        typeof tokenResponse.refresh_token === "string" ? tokenResponse.refresh_token : undefined,
      tokenType: "Bearer",
      expiresAt: expiresIn ? this.clock() + expiresIn : undefined,
      scope: typeof tokenResponse.scope === "string" ? tokenResponse.scope : undefined,
      issuer: metadata.issuer,
      client,
      dynamicClientRegisteredAt: client.registeredAt,
      raw: tokenResponse,
    };
  }

  private assertSecureURL(url: string): void {
    const parsed = new URL(url);
    if (parsed.protocol === "https:") {
      return;
    }
    if (this.allowInsecureHTTP && parsed.protocol === "http:" && isLoopbackHost(parsed.hostname)) {
      return;
    }
    throw new MetadataError(`HTTPS is required for ${parsed.origin}`);
  }

  private assertIssuerURL(url: string): void {
    this.assertSecureURL(url);
    const parsed = new URL(url);
    if (parsed.search || parsed.hash) {
      throw new MetadataError("Authorization server issuer must not include query or fragment");
    }
  }

  private assertEndpointURL(url: string, fieldName: string): void {
    this.assertSecureURL(url);
    const parsed = new URL(url);
    if (parsed.hash) {
      throw new MetadataError(
        `Authorization server metadata ${fieldName} must not include a fragment`,
      );
    }
  }
}
