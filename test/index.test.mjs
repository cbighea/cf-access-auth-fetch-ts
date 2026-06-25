import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";
import {
  AuthManager,
  MemoryTokenStore,
  MetadataError,
  OAuthError,
  authorizationServerMetadataURL,
  createAuthFetch,
  generatePKCE,
  parseWWWAuthenticate,
  protectedResourceMetadataURL,
} from "../dist/index.js";

test("parses multiple WWW-Authenticate challenges", () => {
  const parsed = parseWWWAuthenticate(
    'Basic realm="legacy", Bearer realm="access", resource_metadata="https://app.example/.well-known/oauth-protected-resource/api"',
  );
  assert.equal(parsed.length, 2);
  assert.equal(parsed[1].scheme, "bearer");
  assert.equal(
    parsed[1].params.resource_metadata,
    "https://app.example/.well-known/oauth-protected-resource/api",
  );
});

test("parses quoted commas in WWW-Authenticate parameters", () => {
  const parsed = parseWWWAuthenticate(
    'Bearer realm="access", error_description="needs login, then retry", resource_metadata="https://app.example/.well-known/oauth-protected-resource/api"',
  );
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].params.error_description, "needs login, then retry");
});

test("constructs RFC 9728 metadata URL", () => {
  assert.equal(
    protectedResourceMetadataURL("https://app.example/api/v1?tenant=a"),
    "https://app.example/.well-known/oauth-protected-resource/api/v1?tenant=a",
  );
});

test("constructs RFC 8414 metadata URL without issuer query or fragment", () => {
  assert.equal(
    authorizationServerMetadataURL("https://issuer.example/tenant?ignored=true#fragment"),
    "https://issuer.example/.well-known/oauth-authorization-server/tenant",
  );
});

test("generates PKCE S256 verifier and challenge", () => {
  const pkce = generatePKCE();
  assert.match(pkce.verifier, /^[A-Za-z0-9_-]+$/);
  assert.match(pkce.challenge, /^[A-Za-z0-9_-]+$/);
  assert.notEqual(pkce.verifier, pkce.challenge);
});

test("rejects insecure non-loopback token use", async () => {
  const store = new MemoryTokenStore();
  await store.save({
    resourceURL: "http://example.com/protected",
    accessToken: "access",
    tokenType: "Bearer",
    issuer: "http://example.com",
  });
  const manager = new AuthManager({ store });
  await assert.rejects(
    () => manager.getToken("http://example.com/protected"),
    MetadataError,
  );
});

test("rejects authorization server issuer mismatch", async () => {
  const fixture = await startFixture({ issuerSuffix: "/wrong" });
  try {
    const manager = new AuthManager({ allowInsecureHTTP: true });
    await assert.rejects(() => manager.metadata(fixture.resourceURL), /issuer mismatch/);
  } finally {
    await fixture.close();
  }
});

test("rejects authorization server issuer query or fragment", async () => {
  for (const issuerSuffix of ["?tenant=a", "#fragment"]) {
    const fetch = async (url) => {
      assert.equal(url, "https://app.example/.well-known/oauth-protected-resource");
      return jsonResponse({
        resource: "https://app.example",
        authorization_servers: [`https://issuer.example${issuerSuffix}`],
      });
    };
    const manager = new AuthManager({ fetch });
    await assert.rejects(
      () => manager.metadata("https://app.example"),
      /query or fragment/,
    );
  }
});

test("matches root resource identifiers without adding a slash", async () => {
  const fetch = async (url) => {
    if (url === "https://app.example/.well-known/oauth-protected-resource") {
      return jsonResponse({
        resource: "https://app.example",
        authorization_servers: ["https://issuer.example"],
      });
    }
    assert.equal(url, "https://issuer.example/.well-known/oauth-authorization-server");
    return jsonResponse({
      issuer: "https://issuer.example",
      authorization_endpoint: "https://issuer.example/authorize",
      token_endpoint: "https://issuer.example/token",
      code_challenge_methods_supported: ["S256"],
    });
  };
  const manager = new AuthManager({ fetch });
  const resolved = await manager.metadata("https://app.example");
  assert.equal(resolved.resource.resource, "https://app.example");
});

test("rejects protected resources without Authorization header bearer support", async () => {
  const fixture = await startFixture({ bearerMethods: ["body"] });
  try {
    const manager = new AuthManager({ allowInsecureHTTP: true });
    await assert.rejects(() => manager.metadata(fixture.resourceURL), /Authorization header/);
  } finally {
    await fixture.close();
  }
});

test("rejects unsupported token types", () => {
  const manager = new AuthManager({ store: new MemoryTokenStore() });
  assert.throws(
    () =>
      manager.tokenRecord(
        "https://app.example/protected",
        { issuer: "https://app.example" },
        { clientId: "client-1" },
        { access_token: "access", token_type: "MAC" },
      ),
    OAuthError,
  );
});

test("rejects missing token types", () => {
  const manager = new AuthManager({ store: new MemoryTokenStore() });
  assert.throws(
    () =>
      manager.tokenRecord(
        "https://app.example/protected",
        { issuer: "https://app.example" },
        { clientId: "client-1" },
        { access_token: "access" },
      ),
    /token_type/,
  );
});

test("auth fetch discovers, registers, logs in, and retries", async () => {
  const fixture = await startFixture();
  try {
    const authFetch = createAuthFetch({
      allowInsecureHTTP: true,
      store: new MemoryTokenStore(),
      authorizationCodeProvider(authorizationURL) {
        assert.equal(authorizationURL.searchParams.get("resource"), fixture.resourceURL);
        assert.equal(authorizationURL.searchParams.get("code_challenge_method"), "S256");
        assert.ok(authorizationURL.searchParams.get("code_challenge"));
        return "code-1";
      },
      openBrowser() {},
    });

    const response = await authFetch(fixture.resourceURL);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "ok:access-1");
    assert.equal(fixture.requests.register, 1);
    assert.equal(fixture.requests.token, 1);
    assert.equal(fixture.lastTokenRequest.get("resource"), fixture.resourceURL);
  } finally {
    await fixture.close();
  }
});

test("refreshes expired tokens before request", async () => {
  const fixture = await startFixture();
  const store = new MemoryTokenStore();
  await store.save({
    resourceURL: fixture.resourceURL,
    accessToken: "expired",
    refreshToken: "refresh-1",
    tokenType: "Bearer",
    expiresAt: 1,
    issuer: fixture.baseURL,
    client: { clientId: "client-1" },
  });
  try {
    const manager = new AuthManager({
      allowInsecureHTTP: true,
      store,
      clock: () => 100,
    });
    assert.equal(await manager.getToken(fixture.resourceURL), "access-2");
    assert.equal(fixture.lastTokenRequest.get("grant_type"), "refresh_token");
    assert.equal(fixture.lastTokenRequest.get("resource"), fixture.resourceURL);
  } finally {
    await fixture.close();
  }
});

test("clears token state on invalid refresh grant", async () => {
  const fixture = await startFixture({ invalidRefresh: true });
  const store = new MemoryTokenStore();
  await store.save({
    resourceURL: fixture.resourceURL,
    accessToken: "expired",
    refreshToken: "refresh-1",
    tokenType: "Bearer",
    expiresAt: 1,
    issuer: fixture.baseURL,
    client: { clientId: "client-1" },
  });
  try {
    const manager = new AuthManager({
      allowInsecureHTTP: true,
      store,
      clock: () => 100,
    });
    await assert.rejects(() => manager.refresh(fixture.resourceURL), /invalid or expired/);
    assert.equal(await store.load(fixture.resourceURL), undefined);
  } finally {
    await fixture.close();
  }
});

async function startFixture(options = {}) {
  const requests = { protected: 0, register: 0, token: 0 };
  let baseURL = "";
  let resourceURL = "";
  let lastTokenRequest = new URLSearchParams();
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", baseURL);
    if (url.pathname === "/protected") {
      requests.protected += 1;
      const authorization = request.headers.authorization;
      if (authorization === "Bearer access-1" || authorization === "Bearer access-2") {
        response.end(`ok:${authorization.slice("Bearer ".length)}`);
        return;
      }
      response.writeHead(401, {
        "WWW-Authenticate": `Bearer realm="access", resource_metadata="${baseURL}/.well-known/oauth-protected-resource/protected"`,
      });
      response.end("auth required");
      return;
    }
    if (url.pathname === "/.well-known/oauth-protected-resource/protected") {
      json(response, {
        resource: resourceURL,
        authorization_servers: [baseURL],
        bearer_methods_supported: options.bearerMethods ?? ["header"],
      });
      return;
    }
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      json(response, {
        issuer: `${baseURL}${options.issuerSuffix ?? ""}`,
        authorization_endpoint: `${baseURL}/authorize`,
        token_endpoint: `${baseURL}/token`,
        registration_endpoint: `${baseURL}/register`,
        code_challenge_methods_supported: ["S256"],
      });
      return;
    }
    if (url.pathname === "/register") {
      requests.register += 1;
      const body = JSON.parse(await readBody(request));
      assert.deepEqual(body.grant_types, ["authorization_code", "refresh_token"]);
      assert.equal(body.token_endpoint_auth_method, "none");
      json(response, { client_id: "client-1", redirect_uris: body.redirect_uris });
      return;
    }
    if (url.pathname === "/token") {
      requests.token += 1;
      lastTokenRequest = new URLSearchParams(await readBody(request));
      assert.equal(lastTokenRequest.get("client_id"), "client-1");
      if (lastTokenRequest.get("grant_type") === "authorization_code") {
        assert.equal(lastTokenRequest.get("code"), "code-1");
        assert.equal(lastTokenRequest.get("resource"), resourceURL);
        json(response, {
          access_token: "access-1",
          refresh_token: "refresh-1",
          token_type: options.tokenType ?? "Bearer",
          expires_in: 3600,
          scope: "openid",
        });
        return;
      }
      if (lastTokenRequest.get("grant_type") === "refresh_token") {
        if (options.invalidRefresh) {
          response.writeHead(400, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        assert.equal(lastTokenRequest.get("resource"), resourceURL);
        json(response, {
          access_token: "access-2",
          refresh_token: "refresh-2",
          token_type: "Bearer",
          expires_in: 3600,
        });
        return;
      }
    }
    response.writeHead(404);
    response.end("not found");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  baseURL = `http://127.0.0.1:${port}`;
  resourceURL = `${baseURL}/protected`;
  return {
    baseURL,
    resourceURL,
    requests,
    get lastTokenRequest() {
      return lastTokenRequest;
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let data = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      data += chunk;
    });
    request.on("end", () => resolve(data));
    request.on("error", reject);
  });
}

function json(response, value) {
  response.writeHead(200, {
    "Cache-Control": "max-age=60",
    "Content-Type": "application/json",
  });
  response.end(JSON.stringify(value));
}

function jsonResponse(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: {
      "Cache-Control": "max-age=60",
      "Content-Type": "application/json",
    },
  });
}
