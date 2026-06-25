import { createHash, randomBytes } from "node:crypto";

export function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = randomString(64);
  const challenge = base64URL(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function randomString(size = 32): string {
  return base64URL(randomBytes(size));
}

function base64URL(data: Buffer): string {
  return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
