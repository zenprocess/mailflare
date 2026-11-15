import { sql, type SQL } from "drizzle-orm";
import { users } from "@/db/schema";
import { schemaDialect } from "@/db/dialect";
import type { AppDatabase } from "@/db";

/** A boolean literal that every dialect accepts: PostgreSQL wants `true`/`false`, SQLite and MySQL take 1/0. */
const booleanLiteral = (value: boolean): SQL =>
	schemaDialect() === "postgres" ? sql.raw(value ? "true" : "false") : sql.raw(value ? "1" : "0");

// An INSERT column list must be bare column names, never table-qualified; drizzle
// renders `${users.id}` as "users"."id", which SQLite rejects in that position.
const columns = sql.join(
	[users.id, users.email, users.resetEmail, users.passwordHash, users.name, users.role, users.isPrimaryAdmin, users.remoteContentMode, users.createdAt].map((column) => sql.identifier(column.name)),
	sql`, `,
);

export type CreatePrimaryAdminInput = {
	id: string;
	email: string;
	resetEmail?: string | null;
	passwordHash: string;
	name: string;
};

/**
 * Create the first (primary) account, atomically. The whole statement is a single
 * `INSERT ... SELECT ... WHERE NOT EXISTS`: on SQLite/D1 the single writer lock
 * serialises two concurrent first-run requests, so exactly one of them inserts a
 * row and the other reports zero changed rows. The caller maps `false` to "closed".
 */
export async function insertPrimaryAdmin(
	db: AppDatabase,
	input: CreatePrimaryAdminInput,
	now = Date.now(),
): Promise<boolean> {
	const createdSeconds = Math.floor(now / 1000);
	const result = await db.run(sql`
		INSERT INTO ${users} (${columns})
		SELECT ${input.id}, ${input.email}, ${input.resetEmail ?? null}, ${input.passwordHash}, ${input.name}, ${"admin"}, ${booleanLiteral(true)}, ${"ask"}, ${createdSeconds}
		WHERE NOT EXISTS (SELECT 1 FROM ${users} WHERE ${users.role} = ${"admin"} OR ${users.isPrimaryAdmin} = ${booleanLiteral(true)})
	`);
	return Number((result as { meta?: { changes?: number } }).meta?.changes ?? 0) > 0;
}
