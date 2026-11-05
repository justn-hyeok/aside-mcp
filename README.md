# aside-mcp

Search from the ChatGPT or Claude mobile app using the Aside browser on your Mac.

Those apps call MCP servers from their own clouds, so this server is public behind a Cloudflare Tunnel and OAuth. It listens on loopback only and exposes two read-only tools, `search` and `fetch`. It never exposes Aside's `repl`.

## What protects the browser

- **Fixed scripts.** Tool input is embedded as JSON data in scripts that open a tab, read its text and close it. Nothing clicks, types, or touches your open tabs.
- **URL policy** (`src/policy.ts`). Blocks mail, banking, consoles, work tools, private networks and `justn.me`, both before the tab opens and on the final address after redirects. Add hosts with `ASIDE_MCP_DENY_HOSTS=a.com,b.com`.
- **One-person OAuth** (`src/auth.ts`). PKCE, a password login, codes only for Claude and ChatGPT redirect URLs, and a 15-minute lockout after 5 wrong passwords. Only hashes are stored.
- **Audit log.** `~/Library/Logs/aside-mcp/audit.jsonl` records each tool call.

## What it does not protect

Pages are read with your real cookies. Any logged-in site that is not on the deny list, such as a private GitHub repository, is readable by anything holding a token. A malicious page can also try prompt injection to make the model fetch a URL with data in it. Add sites you care about to the deny list.

## Setup

```sh
bun install
cloudflared tunnel create aside-mcp
cloudflared tunnel route dns aside-mcp <hostname>
bun run set-password        # puts a new password on the clipboard, never prints it
deploy/install.sh <hostname>
```

Aside.app must be running and the Mac awake. Add `https://<hostname>/mcp` as a custom connector in Claude or ChatGPT on the web, then use it from the mobile app.

## Cut off access

```sh
launchctl bootout gui/$UID/me.justn.aside-mcp-tunnel   # takes it off the internet
rm ~/.config/aside-mcp/state.json                      # then restart, to revoke every token
launchctl kickstart -k gui/$UID/me.justn.aside-mcp
```

## Develop

`bun test`, `bun run typecheck`, and `bun run start` (serves http://127.0.0.1:7680).
