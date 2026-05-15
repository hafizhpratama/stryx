#!/usr/bin/env bash
# Publish all 9 Stryx crates to crates.io in dependency order.
#
# Prerequisites (one-time per machine):
#   1. Create a crates.io account at https://crates.io/me (uses GitHub OAuth)
#   2. Generate an API token at https://crates.io/settings/tokens with
#      `publish-new` and `publish-update` scopes for `stryx_*`
#   3. Run `cargo login <token>` once (token persists in ~/.cargo/credentials.toml)
#
# Then from the repo root: ./scripts/cargo-publish.sh
#
# The script sleeps between publishes because crates.io's index takes
# 30-60s to propagate; without the sleeps the next crate's `cargo publish`
# would fail to find its just-published dependency.
#
# Re-runnable: if a crate is already published at the workspace version,
# `cargo publish` errors with `crate version X already uploaded` — this
# is treated as "already done" and the script moves on. Any other
# failure aborts the script so partial state doesn't compound.

set -uo pipefail

# Dependency order:
#   1. stryx_core   — no internal deps
#   2-6. stryx_{ast,cache,taint,reporter,llm}  — all depend on core
#   7. stryx_index  — depends on core, taint
#   8. stryx_rules  — depends on ast, core, index, taint
#   9. stryx_cli    — depends on ast, core, index, rules, reporter, taint
CRATES=(
  stryx_core
  stryx_ast
  stryx_cache
  stryx_taint
  stryx_reporter
  stryx_llm
  stryx_index
  stryx_rules
  stryx_cli
)

# Seconds to wait between publishes for crates.io's index to propagate.
# Empirically 30s is enough; 45s gives margin.
SLEEP_BETWEEN=45

publish_one() {
  local crate=$1
  echo
  echo "═══ publishing $crate ═══"
  if cargo publish -p "$crate"; then
    echo "$crate published OK"
    return 0
  fi
  local exit=$?
  # crates.io returns "crate version X.Y.Z is already uploaded" with
  # exit 101. Detect that vs real failures by re-running with capture.
  local err
  err=$(cargo publish -p "$crate" 2>&1 || true)
  if grep -qE "already (been )?uploaded" <<<"$err"; then
    echo "$crate@$(cargo pkgid -p "$crate" | sed 's/.*#//') already on crates.io — skipping"
    return 0
  fi
  echo "::error::$crate publish failed (exit $exit):"
  echo "$err"
  return 1
}

for i in "${!CRATES[@]}"; do
  crate=${CRATES[$i]}
  if ! publish_one "$crate"; then
    echo "Aborting at $crate. Fix the error, then re-run from this crate onward."
    exit 1
  fi
  # Sleep between every publish except the last one.
  if [[ $i -lt $((${#CRATES[@]} - 1)) ]]; then
    echo "(sleeping ${SLEEP_BETWEEN}s for crates.io index propagation)"
    sleep "$SLEEP_BETWEEN"
  fi
done

echo
echo "═══ all 9 crates published ═══"
echo
echo "End users can now: cargo install stryx_cli"
echo "(Note: the binary is named 'stryx', not 'stryx_cli')"
