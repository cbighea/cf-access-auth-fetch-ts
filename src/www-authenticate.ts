import type { AuthChallenge } from "./types.js";

export function parseWWWAuthenticate(header: string | string[]): AuthChallenge[] {
  const values = Array.isArray(header) ? header : [header];
  return values.flatMap((value) =>
    splitChallenges(value)
      .map((challenge) => {
        const match = challenge.match(/^\s*([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\s*(.*)$/s);
        if (!match) {
          return undefined;
        }
        return {
          scheme: match[1].toLowerCase(),
          params: parseAuthParams(match[2]),
        };
      })
      .filter((challenge): challenge is AuthChallenge => Boolean(challenge)),
  );
}

function splitChallenges(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (char !== "," || quoted) {
      continue;
    }
    const stripped = value.slice(index + 1).trimStart();
    const [token = "", rest = ""] = stripped.split(/\s+/, 2);
    if (token && !token.includes("=") && rest.trim()) {
      parts.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(value.slice(start).trim());
  return parts.filter(Boolean);
}

function parseAuthParams(value: string): Record<string, string> {
  const params: Record<string, string> = {};
  for (const part of splitAuthParamParts(value)) {
    const index = part.indexOf("=");
    if (index < 0) {
      continue;
    }
    const key = part.slice(0, index).trim().toLowerCase();
    let raw = part.slice(index + 1).trim();
    if (raw.startsWith('"') && raw.endsWith('"')) {
      raw = raw.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    }
    params[key] = raw;
  }
  return params;
}

function splitAuthParamParts(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (escaped) {
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      parts.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(value.slice(start).trim());
  return parts.filter(Boolean);
}
