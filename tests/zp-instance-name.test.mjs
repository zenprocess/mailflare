// Zen Labs fork: the Email Routing target follows MAILFLARE_WORKER_NAME; backups use BACKUP_BUCKET when bound.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = mkdtempSync(join(root, "tests", ".tmp-zp-instance-"));
after(() => rmSync(outDir, { recursive: true, force: true }));

await build({
	stdin: {
		contents: 'export * from "./src/lib/cloudflare-api-utils.ts"; export { isMailflareRoutingRule } from "./src/lib/domains/cloudflare-cleanup.ts"; export { getBackupBucket } from "./src/lib/backups/utils.ts";',
		resolveDir: root,
		sourcefile: "zp-instance-entry.ts",
	},
	outfile: join(outDir, "entry.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node22",
	tsconfig: join(root, "tsconfig.json"),
	packages: "external",
	logLevel: "silent",
});
const mod = await import(pathToFileURL(join(outDir, "entry.mjs")).href);

const rule = (worker) => ({ id: "r", matchers: [{ type: "literal", field: "to", value: "a@example.com" }], actions: [{ type: "worker", value: [worker] }] });

test("default worker name stays mailflare", () => {
	mod.setEmailWorkerName(undefined);
	assert.equal(mod.getEmailWorkerName(), "mailflare");
});

test("MAILFLARE_WORKER_NAME selects the routing target and the cleanup predicate", () => {
	mod.setEmailWorkerName("arq-mail-pre");
	assert.equal(mod.getEmailWorkerName(), "arq-mail-pre");
	assert.equal(mod.isMailflareRoutingRule(rule("arq-mail-pre")), true);
	assert.equal(mod.isMailflareRoutingRule(rule("mailflare")), false, "another instance's rules are foreign");
	mod.setEmailWorkerName(undefined);
});

test("malformed worker names fall back to the default", () => {
	for (const bad of ["", "  ", "Arq", "-x", "x-", "a/b", "a".repeat(64), "a b"]) {
		mod.setEmailWorkerName(bad);
		assert.equal(mod.getEmailWorkerName(), "mailflare", JSON.stringify(bad));
	}
	mod.setEmailWorkerName(undefined);
});

test("backups use BACKUP_BUCKET when bound, BUCKET otherwise", () => {
	const BUCKET = { name: "mail" };
	const BACKUP_BUCKET = { name: "backup" };
	assert.equal(mod.getBackupBucket({ BUCKET, BACKUP_BUCKET }), BACKUP_BUCKET);
	assert.equal(mod.getBackupBucket({ BUCKET }), BUCKET);
});
