import {MemoryReferenceStore, type ReferenceKind, type ReferenceStore} from "./store.js";

export interface ComplicatedAuthServerOptions {
  backendUrl: string;
  projectUid: string;
  serviceCredential: string;
  store?: ReferenceStore;
  fetch?: typeof globalThis.fetch;
}

interface BackendSession {
  session_reference: string;
  expires_at: string;
  project_user: {uid: string; [key: string]: unknown};
}

interface BackendLogin {
  login_reference: string;
  expires_at: string;
}

export class ComplicatedAuthServer {
  private readonly runtimeUrl: string;
  private readonly projectUrl: string;
  private readonly serviceCredential: string;
  private readonly store: ReferenceStore;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: ComplicatedAuthServerOptions) {
    const root = options.backendUrl.replace(/\/$/, "");
    this.projectUrl = `${root}/v1/projects/${encodeURIComponent(options.projectUid)}`;
    this.runtimeUrl = `${this.projectUrl}/runtime`;
    this.serviceCredential = options.serviceCredential;
    this.store = options.store ?? new MemoryReferenceStore();
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Web-standard handler suitable for Next.js, Remix, SvelteKit, or Node adapters. */
  async handle(request: Request): Promise<Response> {
    try {
      const path = new URL(request.url).pathname.replace(/^.*\/auth(?=\/|$)/, "");
      if (request.method === "POST" && path === "/login/start") return await this.startLogin(request);
      if (request.method === "POST" && path === "/login/password") return await this.proxyLogin(request, "/login/password");
      if (request.method === "POST" && path === "/login/fido/options") return await this.proxyLogin(request, "/login/fido/options");
      if (request.method === "POST" && path === "/login/fido/verify") return await this.finishLogin(request, "/login/fido/verify");
      if (request.method === "POST" && path === "/login/fido/enrollment/options") return await this.proxyLogin(request, "/login/fido/enrollment/options");
      if (request.method === "POST" && path === "/login/fido/enrollment/verify") return await this.finishLogin(request, "/login/fido/enrollment/verify");
      if (request.method === "POST" && path === "/login/biometric") return await this.finishLogin(request, "/login/biometric");
      if (request.method === "POST" && path === "/enrollments/fido/options") return await this.proxySession(request, "/fido/registration/options");
      if (request.method === "POST" && path === "/enrollments/fido/verify") return await this.proxySession(request, "/fido/registration/verify");
      if (request.method === "POST" && path === "/enrollments/biometric") return await this.proxySession(request, "/biometric/enrollment");
      if (request.method === "DELETE" && path === "/enrollments/biometric") return await this.proxySession(request, "/biometric/enrollment");
      if (request.method === "DELETE" && path.startsWith("/enrollments/fido/")) return await this.deleteFido(request, path.slice("/enrollments/fido/".length));
      if (request.method === "GET" && path === "/session") return await this.session(request);
      if (request.method === "POST" && path === "/logout") return await this.logout(request);
      return problem(404, "not_found", "Authentication endpoint not found");
    } catch (error) {
      return problem(500, "bff_error", error instanceof Error ? error.message : "BFF request failed");
    }
  }

  private async startLogin(request: Request): Promise<Response> {
    const response = await this.backend("/login/start", {method: "POST", body: await request.text()});
    if (!response.ok) return clone(response);
    const value = (await response.json()) as BackendLogin;
    const token = crypto.randomUUID();
    await this.store.set(token, {kind: "login", reference: value.login_reference, expiresAt: value.expires_at});
    return json({login_attempt: token, expires_at: value.expires_at}, 201);
  }

  private async proxyLogin(request: Request, path: string): Promise<Response> {
    const reference = await this.reference(request.headers.get("X-ComplicatedAuth-Login"), "login");
    if (!reference) return problem(401, "invalid_login", "Login attempt is invalid or expired");
    return clone(await this.backend(path, await forward(request, {"X-ComplicatedAuth-Login": reference.reference})));
  }

  private async finishLogin(request: Request, path: string): Promise<Response> {
    const browserToken = request.headers.get("X-ComplicatedAuth-Login");
    const reference = await this.reference(browserToken, "login");
    if (!reference) return problem(401, "invalid_login", "Login attempt is invalid or expired");
    const response = await this.backend(path, await forward(request, {"X-ComplicatedAuth-Login": reference.reference}));
    if (!response.ok) return clone(response);
    const value = (await response.json()) as BackendSession;
    const sessionToken = crypto.randomUUID();
    await this.store.set(sessionToken, {kind: "session", reference: value.session_reference, expiresAt: value.expires_at});
    if (browserToken) await this.store.delete(browserToken);
    return json({session_token: sessionToken, expires_at: value.expires_at, project_user: value.project_user});
  }

  private async proxySession(request: Request, path: string): Promise<Response> {
    const reference = await this.sessionReference(request);
    if (!reference) return problem(401, "invalid_session", "Session is invalid or expired");
    return clone(await this.backend(path, await forward(request, {"X-ComplicatedAuth-Session": reference.reference})));
  }

  private async session(request: Request): Promise<Response> {
    const browserToken = bearer(request);
    const reference = await this.reference(browserToken, "session");
    if (!reference) return problem(401, "invalid_session", "Session is invalid or expired");
    const response = await this.backend("/sessions/introspect", {method: "POST", body: JSON.stringify({session_reference: reference.reference})});
    if (!response.ok) {
      if (browserToken) await this.store.delete(browserToken);
      return clone(response);
    }
    const value = (await response.json()) as {expires_at: string; project_user: unknown};
    return json({session_token: browserToken, expires_at: value.expires_at, project_user: value.project_user});
  }

  private async logout(request: Request): Promise<Response> {
    const browserToken = bearer(request);
    const reference = await this.reference(browserToken, "session");
    if (reference) {
      await this.backend("/sessions/revoke", {method: "POST", body: JSON.stringify({session_reference: reference.reference})});
    }
    if (browserToken) await this.store.delete(browserToken);
    return new Response(null, {status: 204});
  }

  private async deleteFido(request: Request, credentialUid: string): Promise<Response> {
    const reference = await this.sessionReference(request);
    if (!reference) return problem(401, "invalid_session", "Session is invalid or expired");
    const introspection = await this.backend("/sessions/introspect", {method: "POST", body: JSON.stringify({session_reference: reference.reference})});
    if (!introspection.ok) return clone(introspection);
    const value = (await introspection.json()) as {project_user: {uid: string}};
    return clone(await this.rawBackend(`${this.projectUrl}/users/${encodeURIComponent(value.project_user.uid)}/passkeys/${encodeURIComponent(credentialUid)}`, {method: "DELETE"}));
  }

  private async sessionReference(request: Request) {
    return this.reference(bearer(request), "session");
  }

  private async reference(token: string | null, kind: ReferenceKind) {
    if (!token) return null;
    const value = await this.store.get(token);
    return value?.kind === kind ? value : null;
  }

  private backend(path: string, init: RequestInit): Promise<Response> {
    return this.rawBackend(this.runtimeUrl + path, init);
  }

  private rawBackend(url: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${this.serviceCredential}`);
    if (init.body && !headers.has("Content-Type") && typeof init.body === "string") headers.set("Content-Type", "application/json");
    headers.set("Accept", "application/json");
    return this.fetcher(url, {...init, headers, cache: "no-store"});
  }
}

async function forward(request: Request, extra: Record<string, string>): Promise<RequestInit> {
  const headers = new Headers(extra);
  const contentType = request.headers.get("Content-Type");
  if (contentType) headers.set("Content-Type", contentType);
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer();
  const init: RequestInit = {method: request.method, headers};
  if (body !== undefined) init.body = body;
  return init;
}

function bearer(request: Request): string | null {
  const value = request.headers.get("Authorization") ?? "";
  return value.startsWith("Bearer ") ? value.slice(7) : null;
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {status, headers: {"Content-Type": "application/json", "Cache-Control": "no-store"}});
}

function problem(status: number, code: string, message: string): Response {
  return json({error: {code, message}}, status);
}

function clone(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, {status: response.status, statusText: response.statusText, headers});
}
