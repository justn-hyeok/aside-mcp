// HTTP wiring. MCP requests are stateless: each gets its own server and transport, and nothing but
// a valid bearer token reaches them.
import express from "express";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { OwnerAuth } from "./auth.ts";
import { SCOPE } from "./auth.ts";
import type { Browser } from "./browser.ts";
import type { Policy } from "./policy.ts";
import type { Audit } from "./tools.ts";
import { createMcpServer } from "./tools.ts";

export type AppOptions = { publicUrl: URL; auth: OwnerAuth; browser: Browser; policy: Policy; audit: Audit };

export function createApp({ publicUrl, auth, browser, policy, audit }: AppOptions) {
  const mcpUrl = new URL("/mcp", publicUrl);
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", "loopback"); // cloudflared connects from this machine
  app.use(hostHeaderValidation([publicUrl.hostname]));

  app.use(mcpAuthRouter({
    provider: auth,
    issuerUrl: publicUrl,
    resourceServerUrl: mcpUrl,
    resourceName: "Aside Search",
    scopesSupported: [SCOPE],
  }));

  app.post("/oauth/login", express.urlencoded({ extended: false, limit: "8kb" }), auth.handleLogin);

  const bearer = requireBearerAuth({
    verifier: auth,
    expectedResource: mcpUrl,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl),
  });

  app.post("/mcp", bearer, express.json({ limit: "256kb" }), async (req, res) => {
    const server = createMcpServer(browser, policy, audit);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => { void transport.close(); void server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const noStream = (_req: express.Request, res: express.Response) => {
    res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
  };
  app.get("/mcp", bearer, noStream);
  app.delete("/mcp", bearer, noStream);

  return app;
}
