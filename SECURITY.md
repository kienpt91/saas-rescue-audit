# Security

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository (private vulnerability reporting), or email kienphan.dev@gmail.com. Do not file public issues for vulnerabilities.

This is an example project maintained on a best-effort basis. There is no service level and no bug bounty.

## Trust model

`saas-audit` is meant to read repositories that come from someone else, so the audited directory is treated as hostile input. It never executes code from the audited project, never runs `git`, never spawns a process and never uses the network. What it does about hostile input, and what it does not:

- **Files.** Only regular files are read, opened with `O_NOFOLLOW` and `O_NONBLOCK` and checked on the open descriptor (type, then size), so symlinks, FIFOs and devices are neither followed nor able to block the run, including when they replace a file after the directory was listed. The config file in the audited directory is read the same way; a symlink there is refused. A path given with `--config` is the user's own choice and may be a symlink. A `.git` that is a symlink or a regular file is not used. Unreadable files and directories are recorded as skipped. This is not a sandbox: it does not stop the process from reading other files, and it does not defend against a hostile file system or a compromised Node runtime.
- **Limits.** 1 MiB per file, 20 000 files and 64 MiB in total, 64 directory levels, syntax trees no deeper than 1 000 levels, 10 s per file and rule and 120 s overall (cooperative checks in the analysis loops, not preemption). Glob patterns from the config and from `.gitignore` are matched without regular expressions (dynamic programming, no backtracking) and are limited to 256 characters and 16 wildcards. The credential patterns use bounded quantifiers and the line-oriented parsers avoid backtracking patterns. A parse that overflows the stack is caught and recorded. Anything cut off is reported as "Not analysed", marks the JSON report `"complete": false` and gives exit code 3 unless `--allow-incomplete` is passed. A hostile repository can still make a run slow up to these limits, and it can hide code from the audit by exceeding them (which is reported, not silent).
- **Config.** `saas-audit.config.json` is plain JSON, validated strictly (unknown keys rejected, glob patterns checked) and cannot load code. It can switch rules off, exclude paths, mark routes public and name trusted helpers, so a config that ships with the audited repository can reduce what is checked. Everything it changes is printed at the top of every report ("Configuration in effect") and the findings it silences are listed as not counted, together with findings silenced by inline `saas-audit-ignore` comments. Treat the config, and new ignore comments, as security-relevant in a pull-request workflow. Parser error messages from a malformed config are not echoed, because they can quote file content.
- **Output.** File names, policy names, source lines, the package name and warnings come from the repository. The terminal report turns every control character, escape sequence, bidirectional override and zero-width character into a visible escape. The Markdown report escapes markup, HTML, links, mentions, math, pipes and newlines, uses code-span delimiters and fences longer than any backtick run in the content, and prints suggested shell commands with POSIX quoting. The JSON report keeps text exactly as found (JSON escapes control characters); a program that renders it must sanitize it for its own sink. Error messages are sanitized before they are printed.
- **Secrets.** Evidence lines are scrubbed of credential-shaped substrings (known key shapes, JWTs, database URL passwords, private key blocks) before they are truncated, so a secret that straddles the cut is not half printed, and a line whose secret only appears after decoding `\x`/`\u` escapes is withheld. Evidence for a hard-coded secret is built from the match and never from the line. At most the four-character vendor prefix of a key that has one is shown. Secrets the patterns do not recognise (a generic password in a line another rule reports, a key assembled by concatenation) are not removed. The reports can still contain file paths, environment variable names and source lines from the audited project, so treat them as sensitive.

## Limitations

This is a static analyser built from heuristics. It does not prove that code is secure, it produces false positives and false negatives, and it is not a penetration test or a substitute for a code review. The README lists what it does not check. Do not use a clean report as a release gate on its own.

## Dependency policy

Every dependency version, direct and transitive, is installed with `npm install --ignore-scripts --before=<cutoff>`, with exact pins in `package.json` and a committed `package-lock.json` that includes the optional platform packages. A version published after the cutoff (2026-10-24) is not used. Installs, tests, typechecks and builds run in a throwaway container rather than on a developer host, and CI uses `npm ci --ignore-scripts`. No dependency needs an install script. The only runtime dependency of the published package is `typescript` (used for its parser); everything else is a development dependency and `files` is limited to `dist`. `.github/dependabot.yml` uses a 7-day cooldown for npm and GitHub Actions updates, and the workflow pins actions to full commit SHAs with a read-only token. The README's container commands pin the Node image by digest.

## Open advisories

As of the dependency cutoff, `npm audit` reports no advisories, with or without `--omit=dev`.
