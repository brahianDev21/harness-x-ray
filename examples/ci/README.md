# Harness X-Ray in CI

`harness-xray.yml` is an example GitHub Actions workflow for the CI mode of Harness X-Ray (`scripts/ci.mjs`). It is inert: it sits in `examples/`, not in `.github/`, so GitHub never runs it. Copy it to `.github/workflows/` of the repository whose harness you audit, once the placeholders below are replaced.

## What it does

1. Checks out the target (the repository of the pull request) into `target/`, and Harness X-Ray into `harness-x-ray/`, as two folders with `persist-credentials: false`.
2. Runs `node harness-x-ray/scripts/ci.mjs target --fail-on high --sarif harness-x-ray/runs/ci/results.sarif`. The workflow installs nothing: there is no `npm install`, and no code of the target runs. The CI mode runs the measured rules only, with no agent and no judgment rules.
3. Uploads the SARIF log with `github/codeql-action/upload-sarif`, under `if: always()`, so the log is uploaded also when the scan exits 3 (a measured finding at or above `high`). The step sets `checkout_path: target`, because the locations in the log are relative to the target, not to the harness-x-ray checkout.

The workflow has `pull_request` as its only trigger, never `pull_request_target`, and its permissions are `contents: read` and `security-events: write`, nothing else.

## Before you use it

- **Replace the repository placeholder.** `repository: OWNER/harness-x-ray` and `ref: REPLACE-WITH-A-COMMIT-SHA` must name the harness-x-ray repository you trust and a commit of it.
- **Pin the action versions to commit SHAs.** The workflow uses tags (`@v4`, `@v3`). Pinning to a commit SHA is the usual practice for third-party actions; this was not verified against GitHub.
- **The paths filter covers harness files only.** It lists the globs of `data/agent-harness.json`, so the workflow runs when a harness file changes. The measured secret check (SEC-03) and the duplication check (COD-01) look at every file of the target. To cover them, remove the `paths` filter, and expect the workflow to run on every pull request.
- **Judgment rules are not applied.** The CI mode says so in its summary and in the SARIF log. The rules that need reading (for example RUL-01 or SEC-05) are for an agent run with the `xray-scan` skill.
- **Nothing here is verified against GitHub.** The workflow was written without network access. Check the actions, the permissions and the upload against the current GitHub documentation before you rely on it. The `checkout_path` input of the upload step is not verified: whether the action reads it as the root of the repository, and how GitHub resolves the relative SARIF URIs against it, were not checked.

## Exit codes

`scripts/ci.mjs` exits 0 when no measured finding is at or above the threshold, 3 when one is, 2 for a usage or input error, and 1 for anything unexpected. Exit 3 fails the job; the SARIF log is still uploaded because of `if: always()`. Without `--fail-on` the script never exits 3.

## Limits

- A fork's pull request may get a read-only token, and then the SARIF upload cannot write its alerts. This was not verified.
- The SARIF log locates each finding in the files of the target that its evidence names. SEC-03 (a secret) can have evidence in any file of the target, not only in the harness files or the duplicated copies. A finding with no file evidence appears without a location.
