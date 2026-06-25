# cf-access-auth-fetch-ts

Cloudflare Access Managed OAuth aware `fetch` wrapper for Node.js CLIs, SDKs, and other interactive non-browser clients.

Use this package when a Node.js client needs to call a Cloudflare Access protected HTTP application on behalf of a user. It handles Access Managed OAuth discovery, browser login, token storage, refresh, and retrying the original request with an OAuth bearer token.

## Cloudflare setup

Enable [Cloudflare Access Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/) on the protected self-hosted Access application or MCP server portal.

For local CLI flows, configure Managed OAuth to allow the redirect URI style your client uses:

- Allow loopback clients for `127.0.0.1` redirect URIs.
- Allow localhost clients for `localhost` redirect URIs.
- Use a short access token lifetime and a longer grant session duration so the fetch wrapper can refresh silently between interactive logins.

Managed OAuth is intended for user-authenticated clients. Use Cloudflare service tokens instead for unattended machine-to-machine jobs.

## Install

```sh
npm install cf-access-auth-fetch-ts
```

The package requires Node.js 22 or newer.

## Usage

```ts
import { createAuthFetch, FileTokenStore } from "cf-access-auth-fetch-ts";

const authFetch = createAuthFetch({
  store: new FileTokenStore(),
});

const response = await authFetch("https://internal.example.com/api");
console.log(await response.text());
```

The first unauthenticated request receives Cloudflare Access's `401 WWW-Authenticate` challenge, opens the user's browser, completes the authorization-code flow, stores the token, and retries the request. Later requests reuse or refresh the stored token.

## Direct manager use

Use `AuthManager` directly when you want explicit login, logout, metadata, or token control.

```ts
import { AuthManager } from "cf-access-auth-fetch-ts";

const manager = new AuthManager();

const record = await manager.login("https://internal.example.com/api");
const token = await manager.getToken(record.resourceURL);
await manager.logout(record.resourceURL);
```

## Static client fallback

Managed OAuth can dynamically register clients when the Access application allows the redirect URI. If dynamic registration is not available, configure a static client.

```ts
import { AuthManager } from "cf-access-auth-fetch-ts";

const manager = new AuthManager({
  staticClient: {
    clientId: process.env.OAUTH_CLIENT_ID!,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
  },
});
```

For multiple issuers or applications, pass a `staticClient` function that accepts `(issuer, resourceURL)`.

## Token storage

`AuthManager` uses `FileTokenStore` by default. The default path is:

```text
~/.cf-access-auth-fetch/tokens.json
```

The token file is written with `0600` permissions where supported. Use `MemoryTokenStore` for tests or short-lived processes, or implement `TokenStore` to integrate with a platform keychain or another secure store.

## Behavior

- Handles `401 WWW-Authenticate` discovery from Cloudflare Access.
- Prefers RFC 9728 protected resource metadata from the `resource_metadata` challenge parameter.
- Validates the discovered protected resource `resource` exactly.
- Falls back to Cloudflare Managed OAuth's `/.well-known/oauth-authorization-server` endpoint when protected resource metadata is not available.
- Fetches RFC 8414 authorization-server metadata and honors HTTP cache headers.
- Uses authorization-code flow with PKCE S256 only.
- Includes RFC 8707 `resource` in authorization and token requests.
- Uses Dynamic Client Registration when advertised, or a configured static client.
- Stores opaque access tokens without decoding JWTs.
- Refreshes before expiry using a 60 second default skew.

HTTPS is required for resource and metadata URLs by default. Tests can opt into local HTTP with `allowInsecureHTTP: true`.

## Development

```sh
npm install
npm test
```
