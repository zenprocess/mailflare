import type { BackupScheduleType, DatabaseBackupDocument, DatabaseRecord } from "./types";

export const BACKUP_SETTINGS_ID = "default";
export const BACKUP_PREFIX = "backups/database";

/**
 * Zen Labs fork (MAILFLARE-REVIEW.md 8.8): database backups go to a separate R2 bucket
 * (binding BACKUP_BUCKET) so losing or wiping the mail bucket does not take the backups with it.
 * Without the binding the upstream behaviour (same bucket as raw mail) is kept.
 */
export function getBackupBucket(env: CloudflareEnv): R2Bucket {
	return env.BACKUP_BUCKET ?? env.BUCKET;
}

export function isBackupDue(
	scheduleType: BackupScheduleType,
	scheduleValue: number | null,
	now: Date,
): boolean {
	if (scheduleType === "daily") return true;
	if (scheduleType === "weekly") return now.getUTCDay() === scheduleValue;
	return now.getUTCDate() === scheduleValue;
}

export function getUtcDayBounds(now: Date): { start: number; end: number } {
	const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
	return { start, end: start + 86_400_000 };
}

export function createBackupFilename(now: Date): string {
	return `mailflare-${now.toISOString().replace(/[:.]/g, "-")}.json`;
}

/** Moves records from the pre-0019 body table into their message records. */
export function mergeLegacyMessageBodies(document: DatabaseBackupDocument): void {
	const tables = document.tables as Record<string, DatabaseRecord[]>;
	const bodyRows = tables.message_bodies;
	if (!bodyRows) return;

	const bodiesByMessageId = new Map<string, DatabaseRecord>();
	for (const body of bodyRows) {
		if (!isDatabaseRecord(body) || typeof body.message_id !== "string") {
			throw new Error("Backup contains an invalid message_bodies record");
		}
		bodiesByMessageId.set(body.message_id, body);
	}

	for (const message of tables.messages) {
		const body = bodiesByMessageId.get(message.id as string);
		if (!body) continue;
		copyMissingBodyField(message, body, "text_body");
		copyMissingBodyField(message, body, "html_body");
		copyMissingBodyField(message, body, "raw_r2_key");
	}

	delete tables.message_bodies;
}

function copyMissingBodyField(
	message: DatabaseRecord,
	body: DatabaseRecord,
	field: "text_body" | "html_body" | "raw_r2_key",
): void {
	if (!(field in message) && field in body) message[field] = body[field];
}

function isDatabaseRecord(value: unknown): value is DatabaseRecord {
	return !!value && typeof value === "object" && !Array.isArray(value);
}
