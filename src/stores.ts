import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import type { TokenRecord, TokenStore } from "./types.js";
import { isObject } from "./utils.js";

export class MemoryTokenStore implements TokenStore {
  private readonly records = new Map<string, TokenRecord>();

  async load(resourceURL: string): Promise<TokenRecord | undefined> {
    const record = this.records.get(resourceURL);
    return record ? structuredClone(record) : undefined;
  }

  async save(record: TokenRecord): Promise<void> {
    this.records.set(record.resourceURL, structuredClone(record));
  }

  async delete(resourceURL: string): Promise<void> {
    this.records.delete(resourceURL);
  }
}

export class FileTokenStore implements TokenStore {
  readonly filePath: string;

  constructor(filePath = path.join(os.homedir(), ".cf-access-auth-fetch", "tokens.json")) {
    this.filePath = filePath;
  }

  async load(resourceURL: string): Promise<TokenRecord | undefined> {
    const data = await this.readAll();
    const record = data[resourceURL];
    return record ? structuredClone(record) : undefined;
  }

  async save(record: TokenRecord): Promise<void> {
    const data = await this.readAll();
    data[record.resourceURL] = structuredClone(record);
    await this.writeAll(data);
  }

  async delete(resourceURL: string): Promise<void> {
    const data = await this.readAll();
    delete data[resourceURL];
    await this.writeAll(data);
  }

  private async readAll(): Promise<Record<string, TokenRecord>> {
    try {
      const text = await fs.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(text) as unknown;
      return isObject(parsed) ? (parsed as Record<string, TokenRecord>) : {};
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return {};
      }
      throw error;
    }
  }

  private async writeAll(data: Record<string, TokenRecord>): Promise<void> {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    const tmp = `${this.filePath}.${process.pid}.${process.hrtime.bigint()}.tmp`;
    const handle = await fs.open(tmp, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(data, null, 2)}\n`, "utf8");
    } finally {
      await handle.close();
    }
    await fs.rename(tmp, this.filePath);
    await fs.chmod(this.filePath, 0o600).catch(() => undefined);
  }
}
