/** Per-request CSP nonce. Random enough that the next document's nonce is unpredictable. */
export function generateCspNonce(): string {
	if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
		return crypto.randomUUID().replace(/-/g, "");
	}
	return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}
