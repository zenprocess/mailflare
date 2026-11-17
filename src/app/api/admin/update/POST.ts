import { NextResponse } from "next/server";
import { authorizeAdminRequest } from "./utils";

/**
 * Zen Labs fork (MAILFLARE-REVIEW.md 3/8.3): self-update is removed. Upstream dispatched
 * .github/workflows/deploy-update.yml, which replaced the tree with upstream HEAD unreviewed.
 * This fork is pinned; new versions are reviewed, then deployed through the registry
 * (consul.zp.digital), never from the app.
 */
export async function POST(request: Request) {
	const authorization = await authorizeAdminRequest(request);
	if ("error" in authorization) return authorization.error;
	return NextResponse.json(
		{ error: "Self-update is disabled in this build. Updates are reviewed and deployed through the registry." },
		{ status: 410 },
	);
}
