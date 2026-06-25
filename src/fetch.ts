import type { AuthManagerOptions } from "./types.js";
import { InteractionRequiredError } from "./errors.js";
import { AuthManager } from "./manager.js";

export interface AuthFetchOptions extends AuthManagerOptions {
  manager?: AuthManager;
}

export function createAuthFetch(options: AuthFetchOptions = {}): typeof fetch {
  const manager = options.manager ?? new AuthManager(options);
  const fetchImpl = options.fetch ?? fetch;

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const resourceURL = requestURL(input);
    let token: string | undefined;
    try {
      token = await manager.getToken(resourceURL);
    } catch (error) {
      if (!(error instanceof InteractionRequiredError)) {
        throw error;
      }
    }

    let response = await fetchImpl(input, withAuthorization(init, input, token));
    if (response.status !== 401) {
      return response;
    }

    const wwwAuthenticate = response.headers.get("www-authenticate");
    if (token) {
      await manager.refresh(resourceURL);
    } else {
      await manager.login(resourceURL, { wwwAuthenticate });
    }
    token = await manager.getToken(resourceURL);
    return fetchImpl(input, withAuthorization(init, input, token));
  };
}

function requestURL(input: RequestInfo | URL): string {
  if (input instanceof URL) {
    return input.toString();
  }
  if (typeof input === "string") {
    return input;
  }
  return input.url;
}

function withAuthorization(
  init: RequestInit | undefined,
  input: RequestInfo | URL,
  token: string | undefined,
): RequestInit {
  if (!token) {
    return init ?? {};
  }
  const headers = new Headers(
    init?.headers ?? (typeof input !== "string" && !(input instanceof URL) ? input.headers : undefined),
  );
  headers.set("Authorization", `Bearer ${token}`);
  return { ...init, headers };
}
