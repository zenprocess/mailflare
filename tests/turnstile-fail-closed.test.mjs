// Zen Labs fork: Turnstile fails closed when no secret is configured in production.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = mkdtempSync(join(root, "tests", ".tmp-turnstile-"));
after(() => rmSync(outDir, { recursive: true, force: true }));
await build({
	stdin: { contents: 'export { verifyTurnstileToken } from "./src/lib/auth/turnstile.ts";', resolveDir: root, sourcefile: "turnstile-entry.ts" },
	outfile: join(outDir, "entry.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node22",
	tsconfig: join(root, "tsconfig.json"),
	packages: "external",
	logLevel: "silent",
});
const { verifyTurnstileToken } = await import(pathToFileURL(join(outDir, "entry.mjs")).href);

test("no TURNSTILE_SECRET_KEY: closed in production, open in development", async () => {
	const previous = process.env.NODE_ENV;
	try {
		process.env.NODE_ENV = "production";
		assert.equal(await verifyTurnstileToken({}, new Request("https://m.test/"), "anything"), false);
		process.env.NODE_ENV = "development";
		assert.equal(await verifyTurnstileToken({}, new Request("https://m.test/"), undefined), true);
	} finally {
		process.env.NODE_ENV = previous;
	}
});
