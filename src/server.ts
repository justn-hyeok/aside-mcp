import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createApp } from "./app.ts";
import { OwnerAuth } from "./auth.ts";
import { createAsideRepl, createBrowser, serialized } from "./browser.ts";
import { config } from "./config.ts";
import { createPolicy } from "./policy.ts";
import type { Audit } from "./tools.ts";

mkdirSync(dirname(config.auditFile), { recursive: true });

const audit: Audit = (entry) => appendFileSync(config.auditFile, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`, { mode: 0o600 });

const app = createApp({
  publicUrl: config.publicUrl,
  auth: new OwnerAuth({
    mcpUrl: new URL("/mcp", config.publicUrl),
    passwordFile: config.passwordFile,
    stateFile: config.stateFile,
    extraRedirects: config.extraRedirects,
  }),
  browser: createBrowser(serialized(createAsideRepl(config.asideBin)), () => audit({ tool: "closeTab", target: "tab", outcome: "failed" })),
  policy: createPolicy(config.extraDeniedHosts),
  audit,
});

// Loopback only: the tunnel is the one way in from outside.
app.listen(config.port, "127.0.0.1", () => {
  console.log(`aside-mcp on 127.0.0.1:${config.port}, public URL ${config.publicUrl.href}`);
});
