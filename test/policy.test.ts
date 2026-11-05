import { describe, expect, test } from "bun:test";
import { createPolicy, isPrivateAddress } from "../src/policy.ts";

const policy = createPolicy(["blocked.example"], async (host) => (host === "rebind.example.com" ? ["93.184.216.34", "192.168.0.10"] : ["93.184.216.34"]));

describe("urls the browser may open", () => {
  test.each([
    "https://example.com/a?b=c",
    "http://example.com/",
    "https://www.google.com/search?q=x",
    "https://github.com/anthropics/claude-code",
    "https://blog.naver.com/someone/1",
    "https://example.com:443/",
  ])("allows %s", async (url) => {
    expect((await policy.check(url)).ok).toBe(true);
  });

  test.each([
    ["file:///etc/passwd", "local files"],
    ["chrome://settings", "browser pages"],
    ["javascript:alert(1)", "scripts"],
    ["https://user:pw@example.com/", "embedded credentials"],
    ["https://example.com:8443/", "other ports"],
    ["http://localhost/", "localhost"],
    ["http://127.0.0.1/", "loopback"],
    ["http://2130706433/", "loopback as a decimal number"],
    ["http://0x7f.1/", "loopback in hex"],
    ["http://[::1]/", "IPv6 loopback"],
    ["http://[::ffff:127.0.0.1]/", "IPv4-mapped loopback"],
    ["http://192.168.0.1/", "home router"],
    ["http://169.254.169.254/latest/meta-data", "metadata address"],
    ["http://100.74.185.75/", "Tailscale address"],
    ["https://macbookpro.tail993e8d.ts.net/", "tailnet host"],
    ["https://meter.justn.me/", "owner's own services"],
    ["https://intranet/", "single-label host"],
    ["https://mail.google.com/mail/u/0/", "Gmail"],
    ["https://MAIL.GOOGLE.COM./mail", "Gmail spelled to dodge the match"],
    ["https://docs.google.com/document/d/1/edit", "Google Docs"],
    ["https://www.kbstar.com/", "bank subdomain"],
    ["https://github.com/settings/tokens", "GitHub settings"],
    ["https://github.com/SETTINGS", "GitHub settings in capitals"],
    ["https://blocked.example/", "extra denied host"],
    ["https://rebind.example.com/", "public name with a private address"],
  ])("blocks %s (%s)", async (url) => {
    expect((await policy.check(url)).ok).toBe(false);
  });

  test("a lookalike of a denied host stays allowed", async () => {
    expect((await policy.check("https://notmail.google.com.example.com/")).ok).toBe(true);
    expect((await policy.check("https://github.com/settingsfoo")).ok).toBe(true);
  });

  test("a failed lookup blocks instead of passing", async () => {
    const failing = createPolicy([], async () => { throw new Error("no such host"); });
    expect((await failing.check("https://example.com/")).ok).toBe(false);
  });
});

test("isPrivateAddress treats anything it cannot parse as private", () => {
  expect(isPrivateAddress("not-an-ip")).toBe(true);
  expect(isPrivateAddress("8.8.8.8")).toBe(false);
});
