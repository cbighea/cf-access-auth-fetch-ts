import http from "node:http";
import { type AddressInfo } from "node:net";

import { OAuthError } from "./errors.js";

export interface LoopbackServer {
  redirectURI: string;
  waitForCode: Promise<string>;
  close: () => Promise<void>;
}

export async function createLoopbackServer(expectedState: string): Promise<LoopbackServer> {
  let resolveCode: (code: string) => void = () => undefined;
  let rejectCode: (error: Error) => void = () => undefined;
  const waitForCode = new Promise<string>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });
  const server = http.createServer((request, response) => {
    const requestURL = new URL(request.url ?? "/", "http://127.0.0.1");
    const code = requestURL.searchParams.get("code");
    const state = requestURL.searchParams.get("state");
    const error = requestURL.searchParams.get("error");
    response.setHeader("Content-Type", "text/plain; charset=utf-8");
    if (requestURL.pathname === "/callback" && code && state === expectedState) {
      response.end("Authentication complete. You may close this window.");
      resolveCode(code);
    } else {
      response.statusCode = 400;
      response.end("Authentication failed.");
      rejectCode(
        new OAuthError(error ?? "Authorization callback did not include a valid code and state"),
      );
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address() as AddressInfo;
  return {
    redirectURI: `http://127.0.0.1:${address.port}/callback`,
    waitForCode,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
}
