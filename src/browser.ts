// Talks to Aside. Only the fixed scripts in this file ever reach `repl`; a caller supplies data, which is
// embedded as JSON, never code. The scripts open a tab, read text, and close the tab: nothing clicks or types.
import { randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export type Repl = { run(code: string): Promise<string>; close?(): Promise<void> };

export type Engine = "google" | "naver";
export type SearchHit = { title: string; url: string; site?: string };
export type RawPage = { url: string; title: string; text: string };
export type RawSearch = RawPage & { hits: SearchHit[] };

const REPL_TIMEOUT_MS = 90_000;
export const MAX_QUEUED = 8;

export class BrowserBusy extends Error {}

/** Aside drives one browser, so calls run one at a time on a single `aside mcp` child. */
export function createAsideRepl(bin: string): Repl {
  let client: Client | undefined;

  async function connected(): Promise<Client> {
    if (client) return client;
    const next = new Client({ name: "aside-mcp", version: "0.1.0" });
    next.onclose = () => { if (client === next) client = undefined; };
    await next.connect(new StdioClientTransport({ command: bin, args: ["mcp"], env: getDefaultEnvironment(), stderr: "ignore" }));
    client = next;
    return next;
  }

  return {
    async run(code) {
      const session = await connected();
      try {
        const result = await session.callTool({ name: "repl", arguments: { title: "aside-mcp read", code } }, undefined, { timeout: REPL_TIMEOUT_MS });
        const parts = (result.content ?? []) as { type: string; text?: string }[];
        const text = parts.filter((part) => part.type === "text").map((part) => part.text).join("\n");
        if (result.isError) throw new Error(`Aside: ${text.slice(0, 300)}`);
        return text;
      } catch (error) {
        // A stuck REPL would block every later call. Starting over also drops whatever tab it was holding.
        client = undefined;
        await session.close().catch(() => {});
        throw error;
      }
    },
    async close() {
      await client?.close();
    },
  };
}

export function serialized(repl: Repl, maxQueued = MAX_QUEUED): Repl {
  let tail: Promise<unknown> = Promise.resolve();
  let waiting = 0;
  return {
    run(code) {
      if (waiting >= maxQueued) return Promise.reject(new BrowserBusy("the browser is busy, try again shortly"));
      waiting += 1;
      const job = tail.then(() => repl.run(code));
      const settled = job.finally(() => { waiting -= 1; });
      tail = settled.catch(() => {});
      return settled;
    },
    close: () => repl.close?.() ?? Promise.resolve(),
  };
}

/** Wraps a fixed body. The marker is random per call and never enters a page, so page text cannot forge a result. */
function script(body: string, args: unknown, marker: string): string {
  return `await (async () => {
  const args = ${JSON.stringify(args)};
  const emit = (value) => console.log(${JSON.stringify(marker)} + JSON.stringify(value) + ${JSON.stringify(marker)});
  let tab;
  try {
    tab = await openTab(args.url);
    await tab.evaluate(async () => {
      for (let i = 0; i < 12 && (document.body?.innerText ?? "").trim().length < 200; i += 1) {
        await new Promise((done) => setTimeout(done, 250));
      }
    });
${body}
  } catch (error) {
    emit({ error: String(error?.message ?? error).slice(0, 300) });
  } finally {
    if (tab) await closeTab(tab).catch(() => {});
  }
})();`;
}

function parseMarked<T>(output: string, marker: string): T {
  const start = output.indexOf(marker);
  const end = output.lastIndexOf(marker);
  if (start < 0 || end <= start) throw new Error("Aside returned no result");
  const value = JSON.parse(output.slice(start + marker.length, end)) as T | { error: string };
  if (value && typeof value === "object" && "error" in value) throw new Error(`could not read the page: ${value.error}`);
  return value as T;
}

const READ_BODY = `    const read = await tab.evaluate(() => ({ url: location.href, title: document.title, text: document.body?.innerText ?? "" }));
    emit(read);`;

// Result markup changes often, so each extractor is best-effort and `text` always carries the whole page.
const SEARCH_BODY = `    const read = await tab.evaluate((engine) => {
      const clean = (value) => (value ?? "").replace(/새 창 열림/g, "").replace(/\\s+/g, " ").trim();
      const hits = new Map();
      if (engine === "google") {
        for (const heading of document.querySelectorAll("a h3")) {
          const link = heading.closest("a");
          if (!link?.href || hits.has(link.href)) continue;
          hits.set(link.href, { title: clean(heading.innerText), url: link.href, site: clean(link.querySelector("cite")?.innerText) || undefined });
        }
      } else {
        for (const link of document.querySelectorAll('a[href^="http"]')) {
          const title = clean(link.innerText);
          const host = new URL(link.href).hostname;
          if (title.length < 12 || title.length > 120 || host === "search.naver.com" || host === "www.naver.com" || host.startsWith("ader.") || host.startsWith("adcr.") || hits.has(link.href)) continue;
          hits.set(link.href, { title, url: link.href, site: host });
        }
      }
      return { url: location.href, title: document.title, text: document.body?.innerText ?? "", hits: [...hits.values()] };
    }, args.engine);
    emit(read);`;

export function searchUrl(engine: Engine, query: string): string {
  const encoded = encodeURIComponent(query);
  return engine === "google" ? `https://www.google.com/search?q=${encoded}` : `https://search.naver.com/search.naver?query=${encoded}`;
}

export type Browser = {
  read(url: string): Promise<RawPage>;
  search(engine: Engine, query: string): Promise<RawSearch>;
};

export function createBrowser(repl: Repl): Browser {
  async function call<T>(body: string, args: unknown): Promise<T> {
    const marker = `@@${randomBytes(16).toString("hex")}@@`;
    return parseMarked<T>(await repl.run(script(body, args, marker)), marker);
  }
  return {
    read: (url) => call<RawPage>(READ_BODY, { url }),
    search: (engine, query) => call<RawSearch>(SEARCH_BODY, { url: searchUrl(engine, query), engine }),
  };
}
