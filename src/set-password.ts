// Generates the login password and puts it on the clipboard. It is never printed, so it stays out of
// terminal scrollback and agent transcripts. Only its hash is kept. The running server picks it up at once.
import { randomInt } from "node:crypto";
import { savePasswordHash } from "./auth.ts";
import { config } from "./config.ts";

const ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const group = () => Array.from({ length: 6 }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
const password = [group(), group(), group(), group()].join("-");

savePasswordHash(config.passwordFile, password);
const copy = Bun.spawn(["pbcopy"], { stdin: "pipe" });
copy.stdin.write(password);
await copy.stdin.end();
if ((await copy.exited) !== 0) throw new Error("pbcopy failed; run this again");
console.log(`New password is on the clipboard. Save it in Bitwarden. Hash stored at ${config.passwordFile}`);
