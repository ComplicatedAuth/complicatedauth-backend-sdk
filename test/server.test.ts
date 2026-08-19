import {describe, expect, it, vi} from "vitest";
import {ComplicatedAuthServer} from "../src/server.js";

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), {status, headers: {"Content-Type": "application/json"}});

describe("ComplicatedAuthServer", () => {
  it("maps browser login and session tokens without exposing backend references", async () => {
    vi.stubGlobal("crypto", {randomUUID: vi.fn().mockReturnValueOnce("browser-login").mockReturnValueOnce("browser-session")});
    const fetcher = vi.fn()
      .mockResolvedValueOnce(json({login_reference: "backend-login", expires_at: "2099-01-01T00:00:00Z"}, 201))
      .mockResolvedValueOnce(json({session_reference: "backend-session", expires_at: "2099-01-02T00:00:00Z", project_user: {uid: "user-1"}}));
    const server = new ComplicatedAuthServer({backendUrl: "https://auth.internal", projectUid: "project", apiKey: "secret", fetch: fetcher});

    const start = await server.handle(new Request("https://app.test/auth/login/start", {method: "POST", body: JSON.stringify({email: "a@example.com"})}));
    expect(await start.json()).toEqual({login_attempt: "browser-login", expires_at: "2099-01-01T00:00:00Z"});

    const finish = await server.handle(new Request("https://app.test/auth/login/fido/verify", {method: "POST", headers: {"X-ComplicatedAuth-Login": "browser-login"}, body: "{}"}));
    expect(await finish.json()).toEqual({session_token: "browser-session", expires_at: "2099-01-02T00:00:00Z", project_user: {uid: "user-1"}});
    expect(fetcher.mock.calls[1]?.[1]?.headers.get("X-ComplicatedAuth-Login")).toBe("backend-login");
    expect(fetcher.mock.calls[1]?.[1]?.headers.get("Authorization")).toBe("Bearer secret");
  });
});
