# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Security issues in Stryx itself (the scanner, the CLI, or any official
integration) should be reported privately to:

**security@stryx.dev**

If you cannot use email, you can also use GitHub's [private vulnerability
reporting](https://github.com/hafizhpratama/stryx/security/advisories/new).

## What to include

When reporting, please provide:

- A description of the vulnerability
- Steps to reproduce
- Affected version(s) of Stryx
- Any potential impact you've identified
- (Optional) A proposed fix

We do not require a fix to be proposed, but if you have one, it accelerates
remediation.

## What to expect from us

These are best-effort targets, not contractual SLAs. We're a small team
and may take longer when traveling or between releases; we'll keep you
informed.

- **Acknowledgment** — typically within 2 business days
- **Initial assessment** — typically within 7 days, with our
  understanding of severity and a rough remediation timeline
- **Fix timeline** — high-severity issues are prioritized for the next
  release. Lower-severity issues are batched. We provide regular
  updates if a fix takes longer than expected.
- **Public disclosure** — coordinated with you, after the fix is
  released and users have had reasonable time to upgrade
- **Credit** — in the security advisory and CHANGELOG.md if you wish

## Scope

In scope:
- The Stryx scanner engine, CLI, and rules library
- Official integrations: GitHub Action, Vercel hook, Netlify plugin
- The npm package and its prebuilt binaries
- The Stryx website and documentation infrastructure

Out of scope:
- Vulnerabilities in dependencies (please report upstream; we'll update
  promptly once patches are available)
- Issues that require physical access to a user's machine
- Social engineering of Stryx maintainers
- Issues in third-party projects that happen to use Stryx

## Hall of fame

Researchers who report valid vulnerabilities and follow responsible
disclosure are listed (with permission) in our security hall of fame.

## Bug bounties

Stryx does not currently run a paid bug bounty program. We may add one as
the project grows. We genuinely appreciate responsible disclosure regardless.

## Public discussion

Once a vulnerability has been fixed and a patch released, we publish a
GitHub Security Advisory describing the issue, affected versions, and the
fix. We aim for transparency that helps the broader community while
respecting users' time to upgrade.
