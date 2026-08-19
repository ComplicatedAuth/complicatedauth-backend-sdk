export type ReferenceKind = "login" | "session";

export interface StoredReference {
  kind: ReferenceKind;
  reference: string;
  expiresAt: string;
}

export interface ReferenceStore {
  get(token: string): Promise<StoredReference | null>;
  set(token: string, value: StoredReference): Promise<void>;
  delete(token: string): Promise<void>;
}

/** Minimal subset implemented by the official `redis` client. */
export interface RedisReferenceClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options: {PX: number}): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

export interface RedisReferenceStoreOptions {
  client: RedisReferenceClient;
  /** Namespace for browser-safe reference keys. Defaults to `complicatedauth:reference:`. */
  keyPrefix?: string;
}

/** Shared, TTL-backed production store compatible with the official `redis` client. */
export class RedisReferenceStore implements ReferenceStore {
  private readonly client: RedisReferenceClient;
  private readonly keyPrefix: string;

  constructor(options: RedisReferenceStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? "complicatedauth:reference:";
  }

  async get(token: string): Promise<StoredReference | null> {
    const key = this.key(token);
    const raw = await this.client.get(key);
    if (!raw) return null;
    try {
      const value = JSON.parse(raw) as Partial<StoredReference>;
      if ((value.kind !== "login" && value.kind !== "session") || typeof value.reference !== "string" || typeof value.expiresAt !== "string") {
        await this.client.del(key);
        return null;
      }
      if (Date.parse(value.expiresAt) <= Date.now()) {
        await this.client.del(key);
        return null;
      }
      return value as StoredReference;
    } catch {
      await this.client.del(key);
      return null;
    }
  }

  async set(token: string, value: StoredReference): Promise<void> {
    const ttl = Date.parse(value.expiresAt) - Date.now();
    if (!Number.isFinite(ttl) || ttl <= 0) {
      await this.delete(token);
      return;
    }
    await this.client.set(this.key(token), JSON.stringify(value), {PX: ttl});
  }

  async delete(token: string): Promise<void> {
    await this.client.del(this.key(token));
  }

  private key(token: string): string {
    return `${this.keyPrefix}${token}`;
  }
}

/** Development/test store. Production deployments should provide a shared TTL-backed store. */
export class MemoryReferenceStore implements ReferenceStore {
  private readonly values = new Map<string, StoredReference>();

  async get(token: string): Promise<StoredReference | null> {
    const value = this.values.get(token);
    if (!value) return null;
    if (Date.parse(value.expiresAt) <= Date.now()) {
      this.values.delete(token);
      return null;
    }
    return value;
  }
  async set(token: string, value: StoredReference): Promise<void> {
    this.values.set(token, value);
  }
  async delete(token: string): Promise<void> {
    this.values.delete(token);
  }
}
