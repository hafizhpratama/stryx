---
name: Bug report
about: Stryx scanned wrong, crashed, or behaved unexpectedly
title: "[bug] "
labels: bug
assignees: ''
---

## Summary

<!-- One sentence: what went wrong? -->

## Stryx version

```
$ stryx --version
```

## Environment

- OS: <!-- e.g. macOS 14.5, Ubuntu 22.04, Windows 11 -->
- Install method: <!-- npm / brew / cargo / direct binary -->
- Node.js version (if relevant): 
- Rust version (if relevant): 

## Reproduction steps

1. ...
2. ...
3. ...

### Minimal reproducing TypeScript

If possible, include the smallest TypeScript file that reproduces the
issue. If the issue is repo-wide, link to a minimal repo or paste
relevant snippets.

```ts
// paste here
```

### Stryx command

```bash
stryx scan ./repro --some-flag
```

## Expected behavior

<!-- What did you expect to happen? -->

## Actual behavior

<!-- What actually happened? Paste stdout, stderr, exit code if relevant. -->

```
paste output here
```

## Have you tried

- [ ] Updating to the latest Stryx version
- [ ] Running with `--verbose` for more detailed logs
- [ ] Running with `RUST_LOG=stryx=trace` for trace logs
- [ ] Searching existing issues for similar reports

## Additional context

<!-- Anything else that might help us reproduce or diagnose? -->
