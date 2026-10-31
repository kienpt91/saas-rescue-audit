# Security

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository (private vulnerability reporting), or email kienphan.dev@gmail.com. Do not file public issues for vulnerabilities.

This is an example project maintained on a best-effort basis. There is no service level and no bug bounty.

## Trust model

- `saas-audit` reads files from the directory you point it at. It never executes code from the audited project, never runs `git`, never spawns a process and never uses the network.
- Symbolic links are not followed. Files larger than 1 MiB are skipped with a warning, and the config file is limited to 1 MiB.
- `saas-audit.config.json` is plain JSON, validated strictly (unknown keys are rejected) and cannot load code. It can switch rules off, exclude paths and mark routes as public, so in a pull-request workflow treat changes to it, and new `saas-audit-ignore` comments, as security-relevant.
- Evidence printed for secret-shaped values is redacted to a four-character prefix and a length. The report can still contain file paths, environment variable names and source lines from the audited project, so treat reports as sensitive.
- Glob patterns from the config are limited to 256 characters and runs of `*` are collapsed, which bounds regular-expression backtracking.

## Limitations

This is a static analyser built from heuristics. It does not prove that code is secure, it produces false positives and false negatives, and it is not a penetration test or a substitute for a code review. The README lists what it does not check. Do not use a clean report as a release gate on its own.

## Dependency policy

Every dependency version, direct and transitive, is installed with `npm install --ignore-scripts --before=<cutoff>`, with exact pins in `package.json` and a committed `package-lock.json` that includes the optional platform packages. A version published after the cutoff (2026-10-24) is not used. Installs, tests, typechecks and builds run in a throwaway container rather than on a developer host, and CI uses `npm ci --ignore-scripts`. No dependency needs an install script. The only runtime dependency of the published package is `typescript` (used for its parser); everything else is a development dependency and `files` is limited to `dist`. `.github/dependabot.yml` uses a 7-day cooldown for npm and GitHub Actions updates, and the workflow pins actions to full commit SHAs with a read-only token.

## Open advisories

As of the dependency cutoff, `npm audit` reports no advisories, with or without `--omit=dev`.
