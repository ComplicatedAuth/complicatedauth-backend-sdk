import {describe, expect, it} from "vitest";
import {RedisReferenceStore, type RedisReferenceClient} from "../src/store.js";

class FakeRedis implements RedisReferenceClient {
  readonly values = new Map<string, {value: string; expires: number}>();

  async get(key: string): Promise<string | null> {
    const item = this.values.get(key);
    if (!item || item.expires <= Date.now()) {
      this.values.delete(key);
      return null;
    }
    return item.value;
  }

  async set(key: string, value: string, options: {PX: number}): Promise<void> {
    this.values.set(key, {value, expires: Date.now() + options.PX});
  }

  async del(key: string): Promise<void> {
    this.values.delete(key);
  }
}

describe("RedisReferenceStore", () => {
  it("shares references across instances and preserves their TTL", async () => {
    const client = new FakeRedis();
    const first = new RedisReferenceStore({client, keyPrefix: "test:"});
    const second = new RedisReferenceStore({client, keyPrefix: "test:"});
    const reference = {kind: "session" as const, reference: "backend-session", expiresAt: "2099-01-01T00:00:00.000Z"};

    await first.set("browser-token", reference);

    await expect(second.get("browser-token")).resolves.toEqual(reference);
    expect(client.values.get("test:browser-token")?.expires).toBe(Date.parse(reference.expiresAt));
    await second.delete("browser-token");
    await expect(first.get("browser-token")).resolves.toBeNull();
  });

  it("rejects expired and malformed records", async () => {
    const client = new FakeRedis();
    const store = new RedisReferenceStore({client});

    await store.set("expired", {kind: "login", reference: "secret", expiresAt: "2000-01-01T00:00:00.000Z"});
    await expect(store.get("expired")).resolves.toBeNull();

    client.values.set("complicatedauth:reference:bad", {value: "not-json", expires: Date.now() + 10_000});
    await expect(store.get("bad")).resolves.toBeNull();
    expect(client.values.has("complicatedauth:reference:bad")).toBe(false);
  });
});
