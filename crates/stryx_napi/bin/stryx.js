#!/usr/bin/env node
// Thin spawn wrapper around the native `stryx` Rust CLI binary,
// which is bundled in the platform-specific subpackage that npm
// resolves via optionalDependencies.
//
// The full CLI surface — default-scan subcommand, `--verbose`,
// `--diff <base>`, grouped output, Stryx Score, `stryx.toml
// [surfaces]`, `STRYX_DEBUG_DUMP`, profile block, footer — all
// lives in the Rust binary. Re-implementing it in JS would create
// a second source of truth that inevitably drifts; spawning the
// binary directly gives the npm distribution byte-identical
// behavior with the `cargo install` / GitHub Release downloads.
//
// Exit code is forwarded from the child. On a fatal signal we
// re-raise so the parent shell sees the right termination cause.

"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

// Maps `${process.platform}-${process.arch}` to the platform
// subpackage name. Must stay in lockstep with the `napi.targets`
// list in package.json — when a new target is added there, add
// a case here, otherwise users on that platform will see an
// "unsupported platform" error even though they have a binary
// available.
function platformPackageName() {
  const key = `${process.platform}-${process.arch}`;
  switch (key) {
    case "darwin-x64":
      return "@hafizhpratama/stryx-darwin-x64";
    case "darwin-arm64":
      return "@hafizhpratama/stryx-darwin-arm64";
    case "linux-x64":
      return "@hafizhpratama/stryx-linux-x64-gnu";
    case "linux-arm64":
      return "@hafizhpratama/stryx-linux-arm64-gnu";
    case "win32-x64":
      return "@hafizhpratama/stryx-win32-x64-msvc";
    default:
      throw new Error(
        `stryx: unsupported platform ${key}. Pre-built binaries are available for ` +
          "darwin (x64/arm64), linux gnu (x64/arm64), and win32 x64. " +
          "If you need another target, build from source via `cargo install --git " +
          "https://github.com/hafizhpratama/stryx --tag vX.Y.Z stryx_cli`."
      );
  }
}

// Resolve the absolute path to the `stryx` binary inside the
// installed platform subpackage. `require.resolve` finds the
// package regardless of hoist depth (npm/pnpm/yarn handle this
// differently and we want it to work everywhere). The binary
// sits next to the subpackage's package.json.
function resolveBinary() {
  const pkgName = platformPackageName();
  let pkgJsonPath;
  try {
    pkgJsonPath = require.resolve(`${pkgName}/package.json`);
  } catch {
    throw new Error(
      `stryx: platform package "${pkgName}" not found. npm probably skipped its install — ` +
        `try \`npm install --include=optional\` or install the subpackage directly with ` +
        `\`npm install ${pkgName}\`.`
    );
  }
  const dir = path.dirname(pkgJsonPath);
  const binName = process.platform === "win32" ? "stryx.exe" : "stryx";
  const binPath = path.join(dir, binName);
  if (!fs.existsSync(binPath)) {
    throw new Error(
      `stryx: binary not found at ${binPath}. The platform package "${pkgName}" was ` +
        "installed but is missing the CLI binary — please file an issue at " +
        "https://github.com/hafizhpratama/stryx/issues with your OS, arch, and " +
        "install method."
    );
  }
  return binPath;
}

(function main() {
  let binPath;
  try {
    binPath = resolveBinary();
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exit(2);
    return;
  }

  const child = spawn(binPath, process.argv.slice(2), { stdio: "inherit" });

  child.on("error", (err) => {
    process.stderr.write(`stryx: failed to spawn ${binPath}: ${err.message}\n`);
    process.exit(2);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      // Re-raise the signal so the parent shell sees the real
      // termination cause (e.g. Ctrl+C reports SIGINT, not exit 0).
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 1);
    }
  });
})();
