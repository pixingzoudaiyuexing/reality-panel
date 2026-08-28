# Contributing

Thanks for helping improve Reality Panel.

## Commit / PR conventions

- Prefer small, reviewable commits.
- For squash-merged PRs, make sure the PR number appears only once in the final commit message.
- Release and PR-scoped commits should include the correct PR number when applicable.
- Do not rewrite merged history.

## Repository parity reminder

When changing `crates/panel/src/db/{sqlite_repo,pg_repo}`, keep both backend implementations and
contract tests in sync. The PR template includes a checklist item for this.
