export function cacheSeconds(headers: Headers): number {
  const cacheControl = headers.get("cache-control");
  const maxAge = cacheControl?.match(/(?:^|,)\s*max-age=(\d+)/i);
  if (maxAge) {
    return Number(maxAge[1]);
  }
  const expires = headers.get("expires");
  if (expires) {
    const delta = Math.floor((Date.parse(expires) - Date.now()) / 1000);
    if (delta > 0) {
      return delta;
    }
  }
  return 0;
}

export async function safeJSON(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isMetadataFetchFailure(error: Error): boolean {
  return error.message.includes("Metadata request failed with HTTP");
}
