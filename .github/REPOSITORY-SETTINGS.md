# Repository security controls

Workflow files alone cannot enforce repository-hosted controls. After these
files reach `main`, an administrator runs:

```sh
node scripts/configure-github.mjs --apply-security
node scripts/configure-github.mjs --apply-rulesets
node scripts/configure-github.mjs --apply-community
node scripts/configure-github.mjs
```

The first command enables the dependency graph, Dependabot security updates,
secret scanning with push protection, private vulnerability reporting, and
immutable releases. It also requests extended validity/non-provider checks and
reports their effective state; GitHub leaves those disabled when the account
does not have the required Secret Protection entitlement. The second command
refuses to proceed until all required workflows exist on remote `main`; it then
protects `main` with pull requests, resolved conversations, strict required CI,
and force-push/deletion prevention. It also makes `v*` tags non-rewritable and
non-deletable.

The third command enables GitHub Discussions. In repository settings, create a
category named `Commercial inquiries`; the tracked form explicitly forbids secrets,
wallet balances and confidential deal terms. Move the conversation to a private
channel before discussing an organisation or contract.

The required checks cover the supported Node matrix, repository/documentation
contracts, three independent cryptographic/format oracles, macOS release-runtime
behavior, dependency review, CodeQL for JavaScript and Actions, workflow
security linting, and cross-runner reproducibility. Every required workflow is
unconditionally triggered for pull requests so GitHub cannot leave a required
check permanently pending because of a path filter.

The pull-request rule currently requires zero approvals because this is a
single-maintainer repository and GitHub does not let an author approve their
own pull request. Once an independent maintainer is available, raise
`required_approving_review_count` to `1` and enable `require_code_owner_review`
in `scripts/configure-github.mjs`, then re-run `--apply-rulesets`.

Environments `release-candidate` and `release-verification` should restrict
deployment branches/tags to `v*`. Add an independent required reviewer when a
second trusted maintainer exists. Offline release signing keys must never be
stored as Actions secrets: GitHub builds unsigned candidates, while the three
signatures are produced on the isolated signing system described in the release
runbook.
