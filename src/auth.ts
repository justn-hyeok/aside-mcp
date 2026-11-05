// A one-person OAuth 2.1 server. Claude and ChatGPT call from their own clouds, so the endpoint has to be
// public; this is the only thing between the internet and the owner's browser. The SDK's router handles
// PKCE, registration and request validation. This file holds the password, the tokens and the login page.
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Request, Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { InvalidClientMetadataError, InvalidGrantError, InvalidTargetError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";

export const SCOPE = "browse.read";

const ACCESS_TTL_S = 60 * 60;
const REFRESH_TTL_S = 30 * 24 * 60 * 60;
const CODE_TTL_MS = 5 * 60 * 1000;
const PENDING_TTL_MS = 10 * 60 * 1000;
const MAX_PENDING = 20;
const MAX_CLIENTS = 50;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;

/** Only these apps can receive an authorization code, so a stranger's page cannot phish one. */
const REDIRECT_EXACT = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
  "https://chatgpt.com/connector_platform_oauth_redirect",
  "https://platform.openai.com/apps-manage/oauth",
];
const REDIRECT_PREFIX = ["https://chatgpt.com/connector/oauth/"];

export function isAllowedRedirect(uri: string, extra: string[] = []): boolean {
  return REDIRECT_EXACT.includes(uri) || extra.includes(uri) || REDIRECT_PREFIX.some((prefix) => uri.startsWith(prefix));
}

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  return `${salt.toString("hex")}:${scryptSync(password, salt, 32, SCRYPT).toString("hex")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const expected = Buffer.from(hash, "hex");
  return timingSafeEqual(scryptSync(password, Buffer.from(salt, "hex"), expected.length, SCRYPT), expected);
}

const digest = (token: string) => createHash("sha256").update(token).digest("hex");
const newToken = () => randomBytes(32).toString("base64url");
const nowSeconds = () => Math.floor(Date.now() / 1000);

function writePrivate(path: string, content: string) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.tmp`;
  writeFileSync(temp, content, { mode: 0o600 });
  chmodSync(temp, 0o600);
  renameSync(temp, path);
}

export function savePasswordHash(path: string, password: string) {
  writePrivate(path, `${hashPassword(password)}\n`);
}

type StoredToken = { kind: "access" | "refresh"; clientId: string; expiresAt: number };
type State = { clients: Record<string, OAuthClientInformationFull>; tokens: Record<string, StoredToken> };
type Pending = { client: OAuthClientInformationFull; params: AuthorizationParams; expiresAt: number };
type Code = { clientId: string; challenge: string; redirectUri: string; expiresAt: number };

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

export type OwnerAuthOptions = {
  mcpUrl: URL;
  passwordFile: string;
  stateFile: string;
  extraRedirects?: string[];
};

export class OwnerAuth implements OAuthServerProvider {
  private readonly pending = new Map<string, Pending>();
  private readonly codes = new Map<string, Code>();
  private readonly state: State;
  private failures = 0;
  private lockedUntil = 0;

  constructor(private readonly options: OwnerAuthOptions) {
    this.state = existsSync(options.stateFile) ? JSON.parse(readFileSync(options.stateFile, "utf8")) : { clients: {}, tokens: {} };
  }

  private save() {
    const now = nowSeconds();
    for (const [key, token] of Object.entries(this.state.tokens)) {
      if (token.expiresAt <= now) delete this.state.tokens[key];
    }
    writePrivate(this.options.stateFile, JSON.stringify(this.state));
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId) => this.state.clients[clientId],
      registerClient: (client) => {
        const bad = client.redirect_uris.find((uri) => !isAllowedRedirect(String(uri), this.options.extraRedirects));
        if (bad) throw new InvalidClientMetadataError("redirect_uri is not an allowed application");
        const full = { ...client, client_id: randomBytes(16).toString("hex"), client_id_issued_at: nowSeconds() } as OAuthClientInformationFull;
        const ids = Object.keys(this.state.clients);
        if (ids.length >= MAX_CLIENTS) delete this.state.clients[ids[0]!];
        this.state.clients[full.client_id] = full;
        this.save();
        return full;
      },
    };
  }

  private checkResource(resource?: URL) {
    if (resource && resource.href !== this.options.mcpUrl.href) throw new InvalidTargetError("this server only issues tokens for its own MCP endpoint");
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    this.checkResource(params.resource);
    const now = Date.now();
    for (const [key, entry] of this.pending) if (entry.expiresAt <= now) this.pending.delete(key);
    if (this.pending.size >= MAX_PENDING) this.pending.delete(this.pending.keys().next().value!);
    const id = randomBytes(24).toString("base64url");
    this.pending.set(id, { client, params, expiresAt: now + PENDING_TTL_MS });
    this.sendLogin(res, id, client, params.redirectUri);
  }

  private sendLogin(res: Response, id: string, client: OAuthClientInformationFull, redirectUri: string, message?: string, status = 200) {
    const target = new URL(redirectUri);
    // form-action must name the redirect target too: browsers apply it to the redirect after the form posts.
    res.status(status)
      .set({
        "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${target.origin}; frame-ancestors 'none'; base-uri 'none'`,
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
      })
      .type("html")
      .send(`<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aside 검색 연결</title>
<style>:root{color-scheme:light dark}body{font:16px system-ui,sans-serif;max-width:24rem;margin:15vh auto;padding:0 16px}input,button{font:inherit;width:100%;box-sizing:border-box;padding:.75rem;margin-top:.75rem}p{line-height:1.5}.e{color:#d33}</style>
<h1>Aside 검색 연결</h1>
<p><b>${escapeHtml(client.client_name ?? "알 수 없는 앱")}</b> (${escapeHtml(target.host)})이 내 맥북 브라우저로 웹을 검색하고 페이지를 읽으려 합니다.</p>
${message ? `<p class="e">${escapeHtml(message)}</p>` : ""}
<form method="post" action="/oauth/login"><input type="hidden" name="pending" value="${escapeHtml(id)}">
<input type="password" name="password" autocomplete="current-password" placeholder="비밀번호" required autofocus>
<button>허용</button></form></html>`);
  }

  /** Lockout is global on purpose. An attacker can lock the owner out for a while, but cannot keep guessing. */
  handleLogin = (req: Request, res: Response) => {
    const id = String(req.body?.pending ?? "");
    const password = String(req.body?.password ?? "");
    const entry = this.pending.get(id);
    if (!entry || entry.expiresAt <= Date.now()) {
      res.status(400).type("text").send("이 요청은 만료되었습니다. 앱에서 다시 연결해 주세요.");
      return;
    }
    if (Date.now() < this.lockedUntil) {
      this.sendLogin(res, id, entry.client, entry.params.redirectUri, "시도가 너무 많습니다. 15분 뒤에 다시 시도해 주세요.", 429);
      return;
    }
    if (!existsSync(this.options.passwordFile) || !verifyPassword(password, readFileSync(this.options.passwordFile, "utf8").trim())) {
      this.failures += 1;
      if (this.failures >= MAX_FAILURES) {
        this.failures = 0;
        this.lockedUntil = Date.now() + LOCK_MS;
      }
      this.sendLogin(res, id, entry.client, entry.params.redirectUri, "비밀번호가 맞지 않습니다.", 401);
      return;
    }
    this.failures = 0;
    this.pending.delete(id);
    const code = newToken();
    this.codes.set(digest(code), {
      clientId: entry.client.client_id,
      challenge: entry.params.codeChallenge,
      redirectUri: entry.params.redirectUri,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    const target = new URL(entry.params.redirectUri);
    target.searchParams.set("code", code);
    if (entry.params.state) target.searchParams.set("state", entry.params.state);
    res.redirect(302, target.href);
  };

  private liveCode(client: OAuthClientInformationFull, code: string): Code {
    const entry = this.codes.get(digest(code));
    if (!entry || entry.expiresAt <= Date.now() || entry.clientId !== client.client_id) throw new InvalidGrantError("invalid authorization code");
    return entry;
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    return this.liveCode(client, code).challenge;
  }

  private issue(clientId: string): OAuthTokens {
    const access = newToken();
    const refresh = newToken();
    const now = nowSeconds();
    this.state.tokens[digest(access)] = { kind: "access", clientId, expiresAt: now + ACCESS_TTL_S };
    this.state.tokens[digest(refresh)] = { kind: "refresh", clientId, expiresAt: now + REFRESH_TTL_S };
    this.save();
    return { access_token: access, token_type: "bearer", expires_in: ACCESS_TTL_S, refresh_token: refresh, scope: SCOPE };
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens> {
    const entry = this.liveCode(client, code);
    if (redirectUri !== undefined && redirectUri !== entry.redirectUri) throw new InvalidGrantError("redirect_uri does not match");
    this.checkResource(resource);
    this.codes.delete(digest(code));
    return this.issue(client.client_id);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, _scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    const key = digest(refreshToken);
    const entry = this.state.tokens[key];
    if (!entry || entry.kind !== "refresh" || entry.clientId !== client.client_id || entry.expiresAt <= nowSeconds()) throw new InvalidGrantError("invalid refresh token");
    this.checkResource(resource);
    delete this.state.tokens[key];
    return this.issue(client.client_id);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const entry = this.state.tokens[digest(token)];
    if (!entry || entry.kind !== "access" || entry.expiresAt <= nowSeconds()) throw new InvalidTokenError("invalid or expired token");
    return { token, clientId: entry.clientId, scopes: [SCOPE], expiresAt: entry.expiresAt, resource: this.options.mcpUrl };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const key = digest(request.token);
    if (this.state.tokens[key]?.clientId !== client.client_id) return;
    delete this.state.tokens[key];
    this.save();
  }
}
