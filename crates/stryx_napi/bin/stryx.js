#!/usr/bin/env node
// Stryx CLI shim for the napi-rs npm distribution.
//
// Mirrors the Rust CLI's `stryx scan <path>` surface:
//   - `scan` is the only subcommand at v0.2.1
//   - `--format human|json`  (default human)
//   - `--fail-on info|low|medium|high|critical`  (default high)
//
// Exit code: 0 if no findings at or above --fail-on; 1 otherwise.
// Any error (bad args, scan failure, IO error) → exit 2.

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { scan } = require("../index.js");

const SEVERITY_RANK = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function usage() {
  return [
    "stryx — stack-aware security for JavaScript and TypeScript backends",
    "",
    "USAGE:",
    "  stryx scan [PATH] [OPTIONS]",
    "",
    "ARGS:",
    "  PATH                 Path to scan (default: \".\")",
    "",
    "OPTIONS:",
    "  --format <FORMAT>    Output format: human | json (default: human)",
    "  --fail-on <LEVEL>    Minimum severity for non-zero exit",
    "                       (info | low | medium | high | critical; default: high)",
    "  -h, --help           Show this help",
    "  -V, --version        Show version",
    "",
    "EXAMPLES:",
    "  npx stryx scan",
    "  npx stryx scan ./src --format=json",
    "  npx stryx scan . --fail-on=medium",
  ].join("\n");
}

function parseArgs(argv) {
  const args = { _: [], format: "human", failOn: "high" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") {
      args.help = true;
    } else if (a === "-V" || a === "--version") {
      args.version = true;
    } else if (a === "--format") {
      args.format = argv[++i];
    } else if (a.startsWith("--format=")) {
      args.format = a.slice("--format=".length);
    } else if (a === "--fail-on") {
      args.failOn = argv[++i];
    } else if (a.startsWith("--fail-on=")) {
      args.failOn = a.slice("--fail-on=".length);
    } else if (a.startsWith("-")) {
      throw new Error(`unknown flag: ${a}`);
    } else {
      args._.push(a);
    }
  }
  return args;
}

function lineCol(source, byteOffset) {
  // Same semantics as crates/stryx_reporter/src/lib.rs::line_col —
  // 1-indexed line and column counted in chars, not bytes. For
  // ASCII source files (common in TS) bytes and chars coincide;
  // for multi-byte UTF-8 chars, this errs on the side of matching
  // the Rust output.
  let line = 1;
  let col = 1;
  // String#charCodeAt walks UTF-16 code units; we walk bytes via
  // a Buffer view so multi-byte chars don't desync.
  const buf = Buffer.from(source);
  const limit = Math.min(byteOffset, buf.length);
  for (let i = 0; i < limit; i++) {
    if (buf[i] === 0x0a) {
      line += 1;
      col = 1;
    } else {
      col += 1;
    }
  }
  return [line, col];
}

function formatHuman(findings) {
  if (findings.length === 0) {
    return "stryx: no findings\n";
  }
  const sourceCache = new Map();
  const lines = [];
  const summary = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of findings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
    let src = sourceCache.get(f.file);
    if (src === undefined) {
      try {
        src = fs.readFileSync(f.file, "utf8");
      } catch {
        src = null;
      }
      sourceCache.set(f.file, src);
    }
    const [line, col] = src ? lineCol(src, f.start) : [1, 1];
    lines.push(`${f.severity.padEnd(8)} ${f.ruleId}  ${f.file}:${line}:${col}`);
    lines.push(`         ${f.message}`);
    if (f.help) {
      lines.push(`         help: ${f.help}`);
    }
  }
  lines.push("");
  lines.push(
    `${findings.length} finding(s): ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info`,
  );
  return lines.join("\n") + "\n";
}

function formatJson(findings) {
  const summary = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of findings) summary[f.severity] = (summary[f.severity] || 0) + 1;
  return (
    JSON.stringify(
      {
        schema: "stryx.findings/v1",
        findings: findings.map((f) => ({
          rule_id: f.ruleId,
          severity: f.severity,
          message: f.message,
          help: f.help ?? null,
          span: { file: f.file, start: f.start, end: f.end },
        })),
        summary: { total: findings.length, ...summary },
      },
      null,
      2,
    ) + "\n"
  );
}

function maxRank(findings) {
  let max = -1;
  for (const f of findings) {
    const r = SEVERITY_RANK[f.severity];
    if (r !== undefined && r > max) max = r;
  }
  return max;
}

function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`error: ${e.message}\n\n${usage()}\n`);
    return 2;
  }

  if (args.help) {
    process.stdout.write(usage() + "\n");
    return 0;
  }
  if (args.version) {
    const pkg = require("../package.json");
    process.stdout.write(`stryx ${pkg.version}\n`);
    return 0;
  }

  const subcommand = args._[0];
  if (subcommand !== "scan") {
    process.stderr.write(`error: unknown subcommand: ${subcommand ?? "(none)"}\n\n${usage()}\n`);
    return 2;
  }
  const target = args._[1] ?? ".";

  if (SEVERITY_RANK[args.failOn] === undefined) {
    process.stderr.write(`error: unknown --fail-on value: ${args.failOn}\n`);
    return 2;
  }
  if (args.format !== "human" && args.format !== "json") {
    process.stderr.write(`error: unknown --format value: ${args.format}\n`);
    return 2;
  }

  let result;
  try {
    result = scan(path.resolve(target));
  } catch (e) {
    process.stderr.write(`error: scan failed: ${e.message ?? e}\n`);
    return 2;
  }

  const out = args.format === "json"
    ? formatJson(result.findings)
    : formatHuman(result.findings);
  process.stdout.write(out);

  const threshold = SEVERITY_RANK[args.failOn];
  return maxRank(result.findings) >= threshold ? 1 : 0;
}

process.exit(main(process.argv.slice(2)));
