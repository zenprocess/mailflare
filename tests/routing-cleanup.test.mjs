// Zen Labs fork: domain removal deletes only the Email Routing rules Mailflare created.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = mkdtempSync(join(root, "tests", ".tmp-routing-cleanup-"));
after(() => rmSync(outDir, { recursive: true, force: true }));

const rules = [
	{ id: "mf-1", matchers: [{ type: "literal", field: "to", value: "alice@example.com" }], actions: [{ type: "worker", value: ["mailflare"] }] },
	{ id: "fwd-security", matchers: [{ type: "literal", field: "to", value: "security@example.com" }], actions: [{ type: "forward", value: ["sec@zp.test"] }] },
	{ id: "other-worker", matchers: [{ type: "literal", field: "to", value: "bot@example.com" }], actions: [{ type: "worker", value: ["another-worker"] }] },
	{ id: "mf-other-domain", matchers: [{ type: "literal", field: "to", value: "bob@other.com" }], actions: [{ type: "worker", value: ["mailflare"] }] },
	{ id: "mixed", matchers: [{ type: "literal", field: "to", value: "carol@example.com" }], actions: [{ type: "worker", value: ["mailflare"] }, { type: "forward", value: ["x@y.z"] }] },
];

await build({
	stdin: { contents: 'export * from "./src/lib/domains/cloudflare-cleanup.ts";', resolveDir: root, sourcefile: "routing-cleanup-entry.ts" },
	outfile: join(outDir, "entry.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node22",
	tsconfig: join(root, "tsconfig.json"),
	packages: "external",
	logLevel: "silent",
	plugins: [{
		name: "mock-cf",
		setup(b) {
			b.onResolve({ filter: /^@\/lib\/cloudflare-api$/ }, () => ({ path: "cf", namespace: "mock" }));
			b.onLoad({ filter: /.*/, namespace: "mock" }, () => ({
				contents: "export async function listEmailRoutingRules(){return globalThis.__rules;} export async function deleteEmailRoutingRule(env, zone, id){globalThis.__deleted.push(id);}",
				loader: "js",
			}));
		},
	}],
});

const { deleteEmailRoutingRulesForDomain, zoneHasForeignRoutingRules, isMailflareRoutingRule } = await import(pathToFileURL(join(outDir, "entry.mjs")).href);

test("removing a domain deletes only Mailflare's worker rules for that domain", async () => {
	globalThis.__rules = rules;
	globalThis.__deleted = [];
	await deleteEmailRoutingRulesForDomain({}, "zone-1", "Example.com");
	assert.deepEqual(globalThis.__deleted, ["mf-1"]);
});

test("rules Mailflare did not create keep Email Routing on", async () => {
	globalThis.__rules = rules;
	assert.equal(await zoneHasForeignRoutingRules({}, "zone-1"), true);
	globalThis.__rules = [rules[0], rules[3]];
	assert.equal(await zoneHasForeignRoutingRules({}, "zone-1"), false);
	assert.equal(isMailflareRoutingRule({ actions: [] }), false);
});
