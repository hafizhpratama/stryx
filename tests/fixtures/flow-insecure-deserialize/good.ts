// Single-file insecure-deserialization good fixture — every
// handler must produce zero findings under
// `flow/insecure-deserialize`.

import express from "express";
import yaml from "js-yaml";
import { z } from "zod";

const app = express();
app.use(express.json());

// GOOD 1: `yaml.safeLoad` — the documented safe variant. The
// matcher discriminates on the property name `load` vs
// `safeLoad`; this call site must stay silent.
app.post("/yaml", (req, res) => {
  const cfg = yaml.safeLoad(req.body.config);
  res.json({ cfg });
});

// GOOD 2: `JSON.parse` on a request body — JSON has no
// code-execution semantics, so this is safe on its own and is
// deliberately NOT in the sink list. Flagging it would produce
// massive FPs on every Express body-parser usage.
app.post("/json", (req, res) => {
  const parsed = JSON.parse(req.body.payload);
  res.json({ parsed });
});

// GOOD 3: a Zod-validated body that is then passed to a SAFE
// function (no deserialization sink involved at all).
const Input = z.object({ name: z.string().max(64) });
app.post("/safe", (req, res) => {
  const parsed = Input.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "bad input" });
    return;
  }
  greet(parsed.data.name);
  res.json({ ok: true });
});

function greet(_name: string) {
  // no-op — not a deserialization sink.
}

// GOOD 4: yaml.load on a hardcoded string (no request taint).
// The recogniser fires on the call shape, but the rule's
// body-taint walk produces no finding when the argument is
// constant.
export function loadConfigDefaults() {
  return yaml.load("name: defaults\nversion: 1");
}

// GOOD 5: a custom helper named `load` on a non-yaml receiver —
// the receiver name guard excludes everything outside
// {yaml, jsyaml, YAML}. Must stay silent even with body taint.
const settings = {
  load(_input: string) {
    return null;
  },
};
app.post("/settings", (req, res) => {
  settings.load(req.body.blob);
  res.end();
});
