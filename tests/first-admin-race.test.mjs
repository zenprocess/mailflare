import assert from "node:assert/strict";
import test, { after } from "node:test";
import { installSqlite, loadFixture } from "./helpers/fixtures.mjs";

const fixture = await loadFixture({
	name: "first-admin-race",
	entryPoint: "src/lib/auth/primary-admin.ts",
	mocks: {},
});
const { insertPrimaryAdmin } = await fixture.import();
let sqlite;
after(() => { sqlite?.close(); delete globalThis.firstAdminRace; fixture.dispose(); });

const SCHEMA = `CREATE TABLE users (
	id TEXT PRIMARY KEY,
	email TEXT NOT NULL UNIQUE,
	reset_email TEXT,
	password_hash TEXT NOT NULL,
	name TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'user',
	is_primary_admin INTEGER NOT NULL DEFAULT 0,
	remote_content_mode TEXT NOT NULL DEFAULT 'allow',
	created_at INTEGER NOT NULL
);`;

function setup(beforeQuery) {
	sqlite?.close();
	sqlite = installSqlite("firstAdminRace", { schema: SCHEMA, beforeQuery });
}

const admin = (id, email) => ({ id, email, passwordHash: "hashed", name: email.split("@")[0] });
const primaryAdmins = () => sqlite.prepare("SELECT count(*) AS c FROM users WHERE is_primary_admin = 1").get().c;

test("the first setup creates the primary admin", async () => {
	setup();
	assert.equal(await insertPrimaryAdmin(globalThis.firstAdminRace.db, admin("usr_a", "a@example.test")), true);
	assert.equal(primaryAdmins(), 1);
});

test("a second setup after the first inserts no admin", async () => {
	setup();
	assert.equal(await insertPrimaryAdmin(globalThis.firstAdminRace.db, admin("usr_a", "a@example.test")), true);
	assert.equal(await insertPrimaryAdmin(globalThis.firstAdminRace.db, admin("usr_b", "b@example.test")), false);
	assert.equal(primaryAdmins(), 1);
});

test("two simultaneous setups yield exactly one admin", async () => {
	// The competing admin lands immediately before the guarded insert runs, which is
	// the interleaving of the real race: both requests passed the pre-check, then one
	// commits and the other's conditional insert must insert zero rows.
	let injected = false;
	setup((sql, db) => {
		if (!injected && /insert into .*users/i.test(sql)) {
			db.exec("INSERT INTO users (id, email, password_hash, name, role, is_primary_admin, remote_content_mode, created_at) VALUES ('rival','rival@example.test','hashed','Rival','admin',1,'ask',0)");
			injected = true;
		}
	});
	assert.equal(await insertPrimaryAdmin(globalThis.firstAdminRace.db, admin("usr_a", "a@example.test")), false);
	assert.equal(primaryAdmins(), 1);
});

test("a non-admin account does not close registration", async () => {
	setup();
	// Insert an ordinary user first; the guarded insert must still create the admin.
	sqlite.prepare("INSERT INTO users (id, email, password_hash, name, role, is_primary_admin, remote_content_mode, created_at) VALUES ('plain','plain@example.test','hashed','Plain','user',0,'ask',0)").run();
	assert.equal(await insertPrimaryAdmin(globalThis.firstAdminRace.db, admin("usr_a", "a@example.test")), true);
	assert.equal(primaryAdmins(), 1);
});
