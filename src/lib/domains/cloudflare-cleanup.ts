import {
	deleteEmailRoutingRule,
	listEmailRoutingRules,
} from "@/lib/cloudflare-api";
import { getEmailWorkerName } from "@/lib/cloudflare-api-utils";
import type { CfEmailRoutingRule } from "@/lib/cloudflare-api.types";

function routesToDomain(ruleValue: string | undefined, hostname: string): boolean {
	if (!ruleValue) return false;

	const normalized = ruleValue.toLowerCase();
	return normalized === hostname || normalized.endsWith("@" + hostname);
}

/**
 * Zen Labs fork (MAILFLARE-REVIEW.md 8): a rule is Mailflare's only when every action sends the
 * message to this Worker. Mailflare creates nothing else (cloudflare-api.ts
 * ensureEmailRoutingRuleToWorker / createEmailRoutingRuleToWorker), so forwards, drops and rules
 * for other Workers that share the zone (e.g. registry-managed security@ forwards) are never
 * touched.
 */
export function isMailflareRoutingRule(rule: CfEmailRoutingRule, workerName = getEmailWorkerName()): boolean {
	const actions = rule.actions ?? [];
	return actions.length > 0 && actions.every((action) => action.type === "worker" && (action.value ?? []).includes(workerName));
}

export async function deleteEmailRoutingRulesForDomain(
	env: CloudflareEnv,
	zoneId: string,
	hostname: string,
): Promise<void> {
	if (zoneId === "manual") return;
	const normalizedHostname = hostname.toLowerCase();
	const rules = await listEmailRoutingRules(env, zoneId);
	const linkedRules = rules.filter((rule) =>
		isMailflareRoutingRule(rule) &&
		rule.matchers?.some(
			(matcher) =>
				matcher.type === "literal" &&
				matcher.field === "to" &&
				routesToDomain(matcher.value, normalizedHostname),
		),
	);

	await Promise.all(
		linkedRules.map(async (rule) => {
			const ruleId = rule.id ?? rule.tag;
			if (!ruleId) return;

			await deleteEmailRoutingRule(env, zoneId, ruleId);
		}),
	);
}

/**
 * Email Routing is switched off on a zone only when no routing rule that Mailflare did not
 * create is left on it; otherwise other services' forwards would silently stop.
 */
export async function zoneHasForeignRoutingRules(env: CloudflareEnv, zoneId: string): Promise<boolean> {
	if (zoneId === "manual") return false;
	const rules = await listEmailRoutingRules(env, zoneId);
	return rules.some((rule) => rule.matchers?.some((matcher) => matcher.type === "literal") && !isMailflareRoutingRule(rule));
}
