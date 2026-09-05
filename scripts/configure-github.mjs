#!/usr/bin/env node
// Audits GitHub-hosted controls by default. Mutations require an explicit flag;
// branch rules are refused until their workflow definitions exist on main.
import { spawnSync } from "node:child_process";
import process from "node:process";

const args = new Set(process.argv.slice(2));
const repoArg = [...args].find((arg) => arg.startsWith("--repo="));
const applySecurity = args.delete("--apply-security");
const applyRulesets = args.delete("--apply-rulesets");
const applyCommunity = args.delete("--apply-community");
if (repoArg) args.delete(repoArg);
if (args.size) throw new Error(`unknown option(s): ${[...args].join(", ")}`);

function gh(endpoint, { method = "GET", input, tolerate404 = false } = {}) {
  const resource = `repos/${repo}${endpoint ? `/${endpoint}` : ""}`;
  const cli = ["api", resource, "-H", "X-GitHub-Api-Version: 2026-03-10"];
  if (method !== "GET") cli.push("--method", method);
  if (input !== undefined) cli.push("--input", "-");
  const result = spawnSync("gh", cli, {
    encoding: "utf8", input: input === undefined ? undefined : JSON.stringify(input),
  });
  if (result.status !== 0) {
    if (tolerate404 && /HTTP 404|Not Found/i.test(result.stderr)) return null;
    throw new Error(`gh ${endpoint} failed: ${result.stderr.trim()}`);
  }
  const output = result.stdout.trim();
  return output ? JSON.parse(output) : true;
}

function resolveRepo() {
  if (repoArg) return repoArg.slice("--repo=".length);
  const result = spawnSync("gh", ["repo", "view", "--json", "nameWithOwner",
    "--jq", ".nameWithOwner"], { encoding: "utf8" });
  if (result.status !== 0) throw new Error("cannot resolve GitHub repository");
  return result.stdout.trim();
}

const repo = resolveRepo();
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
  throw new Error("--repo must be OWNER/REPO");
}

if (applySecurity) {
  gh("", { method: "PATCH", input: { security_and_analysis: {
    dependency_graph: { status: "enabled" },
    dependabot_security_updates: { status: "enabled" },
    secret_scanning: { status: "enabled" },
    secret_scanning_push_protection: { status: "enabled" },
    secret_scanning_validity_checks: { status: "enabled" },
    secret_scanning_non_provider_patterns: { status: "enabled" },
  } } });
  gh("automated-security-fixes", { method: "PUT" });
  gh("private-vulnerability-reporting", { method: "PUT" });
  gh("immutable-releases", { method: "PUT" });
  process.stdout.write("GitHub security-control update requests completed; verifying effective state.\n");
}

if (applyCommunity) {
  gh("", { method: "PATCH", input: { has_discussions: true } });
  process.stdout.write(
    "GitHub Discussions enabled. Create or rename a category to `Commercial inquiries` " +
      "in repository settings so the tracked discussion form is available there.\n",
  );
}

const workflowPaths = [
  "ci.yml", "dependency-review.yml", "security-analysis.yml", "reproducible-build.yml",
];
const statusChecks = [
  "Node 26.0.0", "Node 26",
  "Repository and documentation contracts",
  "Independent EVM, QR and SLIP-39 oracles",
  "macOS arm64 release-runtime smoke test",
  "Vulnerability and provenance review",
  "CodeQL (javascript-typescript)", "CodeQL (actions)",
  "Workflow syntax and shell analysis", "GitHub Actions security audit",
  "Cross-runner byte equality",
];

function upsertRuleset(payload) {
  const rulesets = gh("rulesets") ?? [];
  const existing = rulesets.find((ruleset) => ruleset.name === payload.name);
  if (existing) {
    gh(`rulesets/${existing.id}`, { method: "PUT", input: payload });
    process.stdout.write(`updated ruleset: ${payload.name}\n`);
  } else {
    gh("rulesets", { method: "POST", input: payload });
    process.stdout.write(`created ruleset: ${payload.name}\n`);
  }
}

if (applyRulesets) {
  for (const workflow of workflowPaths) {
    const present = gh(`contents/.github/workflows/${workflow}?ref=main`, { tolerate404: true });
    if (!present) {
      throw new Error(`refusing ruleset activation: ${workflow} is not yet on remote main`);
    }
  }
  upsertRuleset({
    name: "Protect main with audited CI",
    target: "branch",
    enforcement: "active",
    bypass_actors: [],
    conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } },
    rules: [
      { type: "deletion" },
      { type: "non_fast_forward" },
      { type: "pull_request", parameters: {
        required_approving_review_count: 0,
        dismiss_stale_reviews_on_push: true,
        require_code_owner_review: false,
        require_last_push_approval: false,
        required_review_thread_resolution: true,
      } },
      { type: "required_status_checks", parameters: {
        strict_required_status_checks_policy: true,
        do_not_enforce_on_create: false,
        required_status_checks: statusChecks.map((context) => ({ context })),
      } },
    ],
  });
  upsertRuleset({
    name: "Immutable semantic-version release tags",
    target: "tag",
    enforcement: "active",
    bypass_actors: [],
    conditions: { ref_name: { include: ["refs/tags/v*"], exclude: [] } },
    rules: [{ type: "deletion" }, { type: "non_fast_forward" }],
  });
}

const repository = gh("");
const immutable = gh("immutable-releases", { tolerate404: true });
const privateReporting = gh("private-vulnerability-reporting", { tolerate404: true });
const rulesets = gh("rulesets") ?? [];
const security = repository.security_and_analysis ?? {};
const extendedSecretChecks = [
  security.secret_scanning_validity_checks?.status,
  security.secret_scanning_non_provider_patterns?.status,
];
process.stdout.write(`${JSON.stringify({
  repository: repo,
  discussionsEnabled: repository.has_discussions === true,
  securityAndAnalysis: security,
  extendedSecretChecksEffective: extendedSecretChecks.every((status) => status === "enabled"),
  immutableReleases: immutable !== null,
  privateVulnerabilityReporting: privateReporting !== null,
  rulesets: rulesets.map(({ id, name, enforcement, target }) => ({ id, name, enforcement, target })),
}, null, 2)}\n`);
