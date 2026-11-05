// Runs the real HTTP app with a fake browser, driving OAuth the way a connector does.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, statSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "../src/app.ts";
import { OwnerAuth, savePasswordHash } from "../src/auth.ts";
import type { Browser } from "../src/browser.ts";
import { createPolicy } from "../src/policy.ts";

const PASSWORD = "correct-horse-battery";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const dir = mkdtempSync(join(tmpdir(), "aside-mcp-"));
const audit: { tool: string; target: string; outcome: string }[] = [];
let server: Server;
let base: string;
let mcpUrl: string;
let landing = "https://public.example/landed";
let opened: string[] = [];

const browser: Browser = {
  read: async (url) => { opened.push(url); return { url: landing, title: "Landing", text: "A".repeat(30_000) }; },
  search: async () => ({ url: "https://www.google.com/search?q=x", title: "SERP", text: "results", hits: Array.from({ length: 15 }, (_, i) => ({ title: `Hit ${i}`, url: `https://h${i}.example/`, site: `h${i}.example` })) }),
};
const policy = createPolicy([], async () => ["93.184.216.34"]);

const b64 = (buffer: Buffer) => buffer.toString("base64url");
const form = (values: Record<string, string>) => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(values).toString(), redirect: "manual" as const });

async function register(redirect = REDIRECT) {
  return fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [redirect], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
}

async function startLogin(clientId: string, challenge: string, state = "st4te") {
  const url = new URL(`${base}/authorize`);
  Object.entries({ client_id: clientId, response_type: "code", redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "S256", state, resource: mcpUrl }).forEach(([k, v]) => url.searchParams.set(k, v));
  const response = await fetch(url, { redirect: "manual" });
  const html = await response.text();
  return { response, html, pending: html.match(/name="pending" value="([^"]+)"/)?.[1] ?? "" };
}

async function login(): Promise<{ clientId: string; access: string; refresh: string }> {
  const client = await (await register()).json() as { client_id: string };
  const verifier = b64(randomBytes(32));
  const { pending } = await startLogin(client.client_id, b64(createHash("sha256").update(verifier).digest()));
  const done = await fetch(`${base}/oauth/login`, form({ pending, password: PASSWORD }));
  const code = new URL(done.headers.get("location")!).searchParams.get("code")!;
  const tokens = await (await fetch(`${base}/token`, form({ grant_type: "authorization_code", client_id: client.client_id, code, code_verifier: verifier, redirect_uri: REDIRECT, resource: mcpUrl }))).json() as { access_token: string; refresh_token: string };
  return { clientId: client.client_id, access: tokens.access_token, refresh: tokens.refresh_token };
}

async function rpc(token: string | undefined, method: string, params: unknown = {}) {
  return fetch(mcpUrl, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

async function callTool(token: string, name: string, args: unknown) {
  const body = await (await rpc(token, "tools/call", { name, arguments: args })).json() as { result: { content: { text: string }[]; isError?: boolean } };
  return body.result;
}

beforeAll(async () => {
  savePasswordHash(join(dir, "password"), PASSWORD);
  const port = 17680 + Math.floor(Math.random() * 1000);
  base = `http://127.0.0.1:${port}`;
  mcpUrl = `${base}/mcp`;
  const auth = new OwnerAuth({ mcpUrl: new URL(mcpUrl), passwordFile: join(dir, "password"), stateFile: join(dir, "state.json") });
  const app = createApp({ publicUrl: new URL(base), auth, browser, policy, audit: (entry) => audit.push(entry) });
  await new Promise<void>((ready) => { server = app.listen(port, "127.0.0.1", () => ready()); });
});

afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("without a valid token", () => {
  test("/mcp answers 401 and points at the OAuth metadata", async () => {
    const response = await rpc(undefined, "tools/list");
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("oauth-protected-resource/mcp");
    const meta = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json() as { resource: string };
    expect(meta.resource).toBe(mcpUrl);
  });

  test("a made-up token is rejected and the browser is not touched", async () => {
    opened = [];
    expect((await rpc("made-up", "tools/call", { name: "fetch", arguments: { id: "https://public.example/" } })).status).toBe(401);
    expect(opened).toEqual([]);
  });

  test("a foreign Host header is rejected, which stops DNS rebinding", async () => {
    const response = await fetch(`${base}/.well-known/oauth-authorization-server`, { headers: { host: "evil.example" } });
    expect(response.status).toBe(403);
  });
});

describe("authorization", () => {
  test("registering a redirect outside the allowed apps fails", async () => {
    expect((await register("https://evil.example/callback")).status).toBe(400);
  });

  test("the wrong PKCE verifier gets no token and the code is not issued without a password", async () => {
    const client = await (await register()).json() as { client_id: string };
    const verifier = b64(randomBytes(32));
    const { pending, response, html } = await startLogin(client.client_id, b64(createHash("sha256").update(verifier).digest()));
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("content-security-policy")).toContain("form-action 'self' https://claude.ai");
    expect(html).not.toContain(PASSWORD);
    const denied = await fetch(`${base}/oauth/login`, form({ pending, password: "wrong" }));
    expect(denied.status).toBe(401);
    expect(denied.headers.get("location")).toBeNull();
    const done = await fetch(`${base}/oauth/login`, form({ pending, password: PASSWORD }));
    const location = new URL(done.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get("state")).toBe("st4te");
    const code = location.searchParams.get("code")!;
    const bad = await fetch(`${base}/token`, form({ grant_type: "authorization_code", client_id: client.client_id, code, code_verifier: b64(randomBytes(32)), redirect_uri: REDIRECT }));
    expect(bad.status).toBe(400);
  });

  test("a code works once, and a used login link cannot be replayed", async () => {
    const client = await (await register()).json() as { client_id: string };
    const verifier = b64(randomBytes(32));
    const { pending } = await startLogin(client.client_id, b64(createHash("sha256").update(verifier).digest()));
    const done = await fetch(`${base}/oauth/login`, form({ pending, password: PASSWORD }));
    const code = new URL(done.headers.get("location")!).searchParams.get("code")!;
    const exchange = () => fetch(`${base}/token`, form({ grant_type: "authorization_code", client_id: client.client_id, code, code_verifier: verifier, redirect_uri: REDIRECT }));
    expect((await exchange()).status).toBe(200);
    expect((await exchange()).status).toBe(400);
    expect((await fetch(`${base}/oauth/login`, form({ pending, password: PASSWORD }))).status).toBe(400);
  });

  test("a token for another resource is refused", async () => {
    const client = await (await register()).json() as { client_id: string };
    const url = new URL(`${base}/authorize`);
    Object.entries({ client_id: client.client_id, response_type: "code", redirect_uri: REDIRECT, code_challenge: "x".repeat(43), code_challenge_method: "S256", resource: "https://other.example/mcp" }).forEach(([k, v]) => url.searchParams.set(k, v));
    const response = await fetch(url, { redirect: "manual" });
    expect(response.headers.get("location")).toContain("error=invalid_target");
  });

  test("refresh rotates: the new token works and the old refresh token does not", async () => {
    const { clientId, refresh } = await login();
    const renew = () => fetch(`${base}/token`, form({ grant_type: "refresh_token", client_id: clientId, refresh_token: refresh }));
    const first = await renew();
    expect(first.status).toBe(200);
    const { access_token } = await first.json() as { access_token: string };
    expect((await rpc(access_token, "tools/list")).status).toBe(200);
    expect((await renew()).status).toBe(400);
  });

  test("the state file holds no usable token and is private", async () => {
    const { access } = await login();
    const path = join(dir, "state.json");
    expect(readFileSync(path, "utf8")).not.toContain(access);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  test("repeated wrong passwords lock login, even for the right password", async () => {
    const lockDir = mkdtempSync(join(tmpdir(), "aside-mcp-lock-"));
    savePasswordHash(join(lockDir, "password"), PASSWORD);
    const port = 18680 + Math.floor(Math.random() * 1000);
    const lockBase = `http://127.0.0.1:${port}`;
    const auth = new OwnerAuth({ mcpUrl: new URL(`${lockBase}/mcp`), passwordFile: join(lockDir, "password"), stateFile: join(lockDir, "state.json") });
    const app = createApp({ publicUrl: new URL(lockBase), auth, browser, policy, audit: () => {} });
    const lockServer = await new Promise<Server>((ready) => { const s = app.listen(port, "127.0.0.1", () => ready(s)); });
    try {
      const client = await (await fetch(`${lockBase}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }) })).json() as { client_id: string };
      const url = new URL(`${lockBase}/authorize`);
      Object.entries({ client_id: client.client_id, response_type: "code", redirect_uri: REDIRECT, code_challenge: "x".repeat(43), code_challenge_method: "S256" }).forEach(([k, v]) => url.searchParams.set(k, v));
      const pending = (await (await fetch(url)).text()).match(/name="pending" value="([^"]+)"/)![1]!;
      for (let i = 0; i < 5; i += 1) {
        expect((await fetch(`${lockBase}/oauth/login`, form({ pending, password: "nope" }))).status).toBe(401);
      }
      const locked = await fetch(`${lockBase}/oauth/login`, form({ pending, password: PASSWORD }));
      expect(locked.status).toBe(429);
      expect(locked.headers.get("location")).toBeNull();
    } finally {
      lockServer.close();
      rmSync(lockDir, { recursive: true, force: true });
    }
  });
});

describe("tools", () => {
  let token: string;
  beforeAll(async () => { token = (await login()).access; });

  test("exactly search and fetch are exposed, both marked read-only", async () => {
    const body = await (await rpc(token, "tools/list")).json() as { result: { tools: { name: string; annotations: { readOnlyHint: boolean } }[] } };
    expect(body.result.tools.map((tool) => tool.name).sort()).toEqual(["fetch", "search"]);
    expect(body.result.tools.every((tool) => tool.annotations.readOnlyHint)).toBe(true);
  });

  test("repl cannot be called", async () => {
    const result = await callTool(token, "repl", { code: "console.log(1)", title: "x" });
    expect(result.isError).toBe(true);
  });

  test("search caps results and uses the id/title/url shape", async () => {
    const result = await callTool(token, "search", { query: "x" });
    const parsed = JSON.parse(result.content[0]!.text);
    expect(parsed.results.length).toBe(10);
    expect(parsed.results[0]).toEqual({ id: "https://h0.example/", title: "Hit 0", url: "https://h0.example/", site: "h0.example" });
  });

  test("fetch pages through long text", async () => {
    landing = "https://public.example/landed";
    const first = JSON.parse((await callTool(token, "fetch", { id: "https://public.example/" })).content[0]!.text);
    expect(first.text.length).toBe(12_000);
    expect(first.metadata).toEqual({ total_chars: 30_000, next_offset: 12_000 });
    const last = JSON.parse((await callTool(token, "fetch", { id: "https://public.example/", offset: 24_000 })).content[0]!.text);
    expect(last.text.length).toBe(6_000);
    expect(last.metadata.next_offset).toBeNull();
  });

  test("a denied URL never opens a tab", async () => {
    opened = [];
    const result = await callTool(token, "fetch", { id: "https://mail.google.com/mail/" });
    expect(result.isError).toBe(true);
    expect(opened).toEqual([]);
    expect(audit.at(-1)).toMatchObject({ tool: "fetch", outcome: "blocked" });
  });

  test("a redirect onto a private page returns none of its text", async () => {
    landing = "https://mail.google.com/mail/u/0/";
    const result = await callTool(token, "fetch", { id: "https://www.google.com/goto?url=abc" });
    landing = "https://public.example/landed";
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("Blocked after redirect");
    expect(result.content[0]!.text).not.toContain("AAAA");
    expect(audit.at(-1)).toMatchObject({ outcome: "blocked-after-redirect" });
  });
});
