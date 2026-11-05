// Decides which URLs the gateway may read. The browser holds the owner's real logins, so a URL is checked
// twice: before the tab opens, and again on the address the page ended up at after redirects.
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

/** Sites that hold private data behind the owner's login. A host matches itself and its subdomains. */
export const DENIED_HOSTS = [
  // Mail, files, calendars
  "mail.google.com", "accounts.google.com", "myaccount.google.com", "drive.google.com", "docs.google.com",
  "calendar.google.com", "contacts.google.com", "photos.google.com", "pay.google.com", "takeout.google.com",
  "outlook.live.com", "outlook.office.com", "outlook.office365.com", "login.microsoftonline.com",
  "login.live.com", "account.microsoft.com", "onedrive.live.com", "icloud.com", "appleid.apple.com",
  "mail.naver.com", "nid.naver.com", "pay.naver.com", "calendar.naver.com", "mybox.naver.com",
  "mail.daum.net", "accounts.kakao.com", "pay.kakao.com",
  // Work tools and developer consoles
  "slack.com", "discord.com", "teams.microsoft.com", "notion.so", "linear.app", "figma.com",
  "vercel.com", "dash.cloudflare.com", "console.aws.amazon.com", "console.cloud.google.com",
  "portal.azure.com", "login.tailscale.com", "vault.bitwarden.com",
  // AI accounts
  "claude.ai", "console.anthropic.com", "chatgpt.com", "platform.openai.com",
  // Money
  "kbstar.com", "shinhan.com", "wooribank.com", "hanabank.com", "ibk.co.kr", "nonghyup.com", "kakaobank.com",
  "tossbank.com", "toss.im", "paypal.com", "stripe.com",
];

/** Private areas of sites that are otherwise public. A path matches itself and anything below it. */
export const DENIED_PATHS: Record<string, string[]> = {
  "github.com": ["/settings", "/notifications"],
  "x.com": ["/messages", "/settings"],
  "instagram.com": ["/direct", "/accounts"],
  "facebook.com": ["/messages", "/settings"],
  "linkedin.com": ["/messaging", "/mypreferences"],
};

const DENIED_SUFFIXES = ["localhost", "local", "internal", "intranet", "lan", "home", "ts.net", "justn.me"];

const privateAddresses = new BlockList();
privateAddresses.addSubnet("0.0.0.0", 8);
privateAddresses.addSubnet("10.0.0.0", 8);
privateAddresses.addSubnet("100.64.0.0", 10); // Tailscale and carrier NAT
privateAddresses.addSubnet("127.0.0.0", 8);
privateAddresses.addSubnet("169.254.0.0", 16);
privateAddresses.addSubnet("172.16.0.0", 12);
privateAddresses.addSubnet("192.168.0.0", 16);
privateAddresses.addSubnet("198.18.0.0", 15);
privateAddresses.addSubnet("224.0.0.0", 3);
privateAddresses.addAddress("::", "ipv6");
privateAddresses.addAddress("::1", "ipv6");
privateAddresses.addSubnet("fc00::", 7, "ipv6");
privateAddresses.addSubnet("fe80::", 10, "ipv6");
privateAddresses.addSubnet("ff00::", 8, "ipv6");

export function isPrivateAddress(address: string): boolean {
  const mapped = address.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return privateAddresses.check(mapped[1]!, "ipv4");
  const family = isIP(address);
  if (family === 0) return true;
  return privateAddresses.check(address, family === 6 ? "ipv6" : "ipv4");
}

function matchesHost(host: string, denied: string): boolean {
  return host === denied || host.endsWith(`.${denied}`);
}

export type Verdict = { ok: true; url: URL } | { ok: false; reason: string };
export type Resolve = (host: string) => Promise<string[]>;

export type Policy = {
  check(raw: string): Promise<Verdict>;
};

const systemResolve: Resolve = async (host) => (await lookup(host, { all: true })).map((entry) => entry.address);

export function createPolicy(extraDeniedHosts: string[] = [], resolve: Resolve = systemResolve): Policy {
  const deniedHosts = [...DENIED_HOSTS, ...extraDeniedHosts.map((host) => host.toLowerCase())];

  return {
    async check(raw) {
      let url: URL;
      try {
        url = new URL(raw);
      } catch {
        return { ok: false, reason: "not a valid URL" };
      }
      if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false, reason: "only http and https are allowed" };
      if (url.username || url.password) return { ok: false, reason: "URLs with credentials are not allowed" };
      if (url.port && url.port !== "80" && url.port !== "443") return { ok: false, reason: "non-standard ports are not allowed" };

      // URL normalizes IPv4 spellings like 2130706433 or 0x7f.1 to dotted form; IPv6 keeps its brackets.
      const host = url.hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
      if (isIP(host)) {
        if (isPrivateAddress(host)) return { ok: false, reason: "private addresses are not allowed" };
      } else {
        if (!host.includes(".")) return { ok: false, reason: "single-label hosts are not allowed" };
        if (DENIED_SUFFIXES.some((suffix) => matchesHost(host, suffix))) return { ok: false, reason: `${host} is private` };
        if (deniedHosts.some((denied) => matchesHost(host, denied))) return { ok: false, reason: `${host} holds private account data` };
      }
      for (const [site, paths] of Object.entries(DENIED_PATHS)) {
        if (!matchesHost(host, site)) continue;
        const path = url.pathname.toLowerCase();
        if (paths.some((denied) => path === denied || path.startsWith(`${denied}/`))) {
          return { ok: false, reason: `${site}${url.pathname} is a private page` };
        }
      }

      if (!isIP(host)) {
        let addresses: string[];
        try {
          addresses = await resolve(host);
        } catch {
          return { ok: false, reason: `could not resolve ${host}` };
        }
        if (addresses.some(isPrivateAddress)) return { ok: false, reason: `${host} points at a private address` };
      }
      return { ok: true, url };
    },
  };
}
