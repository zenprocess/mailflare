/**
 * Bundle the vinext build into ONE ESM file for the ZenInfra registry.
 *
 * `npm run build` (vp build) writes `dist/server/index.js` plus 797 code-split modules
 * under `dist/server/_next/` and `dist/server/ssr/`. Native `wrangler deploy` uploads those
 * as separate modules; the registry (POST /workers) accepts a single `script` string, so this
 * inlines them with the same esbuild wrangler ships (resolved through wrangler's own tree, not
 * added to package.json), keeping `cloudflare:*`, `node:*`, the bare Node builtins and
 * `bun:*` external — workerd provides the first two under nodejs_compat, and `bun:sqlite` is a
 * dynamic import on the Node-only DB driver path that Workers never takes.
 *
 * This proves module resolution + bundling and prints the size. It does NOT run wrangler's own
 * checks (binding validation, upload size limit, DO migration diff) — see README "Deploy through
 * the ZenInfra registry".
 */
import { createRequire, builtinModules } from 'node:module'
import { fileURLToPath } from 'node:url'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

const root = fileURLToPath(new URL('..', import.meta.url))
const serverDir = join(root, 'dist', 'server')
const entry = join(serverDir, 'index.js')
const outfile = join(root, 'dist', 'mailflare-worker.mjs')

export async function bundleWorker() {
	if (!existsSync(entry)) {
		throw new Error(`${entry} is missing — run "npm run build" first`)
	}
	const req = createRequire(join(root, 'package.json'))
	const wranglerPkg = req.resolve('wrangler/package.json')
	const esbuild = createRequire(wranglerPkg)('esbuild')

	// Bare Node builtin names (workerd resolves them under nodejs_compat); 'node:*' covers the
	// prefixed form, so list the bare names only.
	const bareBuiltins = [...new Set(builtinModules.map((name) => (name.startsWith('node:') ? name.slice(5) : name)))]

	const result = await esbuild.build({
		entryPoints: [entry],
		absWorkingDir: serverDir,
		bundle: true,
		write: true,
		outfile,
		format: 'esm',
		platform: 'neutral',
		target: 'es2022',
		conditions: ['workerd', 'worker', 'browser', 'import', 'module', 'default'],
		mainFields: ['module', 'main'],
		external: ['cloudflare:*', 'node:*', 'bun:*', ...bareBuiltins],
		minify: true,
		logLevel: 'silent',
		metafile: true,
	})

	const bytes = statSync(outfile).size
	const gzipBytes = gzipSync(readFileSync(outfile)).byteLength
	const outputs = Object.values(result.metafile.outputs)
	const externals = [...new Set(outputs.flatMap((o) => o.imports.filter((i) => i.external).map((i) => i.path)))]
	const exports = [...new Set(outputs.flatMap((o) => o.exports))]
	return {
		esbuildVersion: esbuild.version,
		inputs: Object.keys(result.metafile.inputs).length,
		bytes,
		gzipBytes,
		warnings: result.warnings,
		externals,
		exports,
	}
}

if (import.meta.url === `file://${process.argv[1]}`) {
	const r = await bundleWorker()
	console.log(
		`worker bundle ok · esbuild ${r.esbuildVersion} · ${r.inputs} inputs · ` +
		`${(r.bytes / 1024).toFixed(0)} KiB minified (${(r.gzipBytes / 1024).toFixed(0)} KiB gzip) · ${r.warnings.length} warnings`,
	)
	console.log(`  exports: ${r.exports.join(', ')}`)
	console.log(`  externals (${r.externals.length}): ${r.externals.join(', ')}`)
}

