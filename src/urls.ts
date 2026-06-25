export function protectedResourceMetadataURL(resourceURL: string): string {
  const url = new URL(normalizeResourceURL(resourceURL));
  const suffix = url.pathname === "/" ? "" : url.pathname;
  return `${url.origin}/.well-known/oauth-protected-resource${suffix}${url.search}`;
}

export function authorizationServerMetadataURL(issuer: string): string {
  const url = new URL(issuer);
  const suffix = url.pathname === "/" ? "" : trimTrailingSlash(url.pathname);
  return `${url.origin}/.well-known/oauth-authorization-server${suffix}`;
}

export function cloudflareAuthorizationServerMetadataURL(resourceURL: string): string {
  const url = new URL(normalizeResourceURL(resourceURL));
  return `${url.origin}/.well-known/oauth-authorization-server`;
}

export function normalizeResourceURL(resourceURL: string): string {
  const fragmentIndex = resourceURL.indexOf("#");
  const withoutFragment =
    fragmentIndex >= 0 ? resourceURL.slice(0, fragmentIndex) : resourceURL;
  new URL(withoutFragment);
  return withoutFragment;
}

export function resourceOrigin(resourceURL: string): string {
  const url = new URL(resourceURL);
  return url.origin;
}

export function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}
