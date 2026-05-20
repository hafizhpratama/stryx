// Single-file insecure-deserialization fixture for
// `flow/insecure-deserialize` slice 1. Each handler is an
// independent case the rule must flag at Critical severity.
//
// Real-world repro: DVNA's `core/appHandler.js` imports
// `node-serialize` and feeds `req.body` straight into
// `serialize.unserialize`, producing canonical RCE on the
// `/import` endpoint. Same shape with `yaml.load(req.body...)`
// and `vm.runInNewContext(req.body...)`.

import express from "express";
import serialize from "node-serialize";
import yaml from "js-yaml";
import vm from "vm";

const app = express();
app.use(express.json());

// CASE 1: node-serialize unserialize on req.body — direct RCE.
// node-serialize evaluates `IIFE`-wrapped function payloads on
// parse; an attacker payload like
//   {"x":"_$$ND_FUNC$$_function(){require('child_process').exec(...)}()"}
// triggers code execution at the moment `unserialize` runs.
app.post("/import", (req, res) => {
  const obj = serialize.unserialize(req.body.payload);
  res.json({ obj });
});

// CASE 2: js-yaml `yaml.load` on req.body — RCE via the unsafe
// schema. `yaml.load` (NOT `yaml.safeLoad`) resolves the
// `!!js/function` tag and will materialise a JS function from
// the document.
app.post("/yaml", (req, res) => {
  const cfg = yaml.load(req.body.config);
  res.json({ cfg });
});

// CASE 3: `vm.runInNewContext` on req.body — runs the string as
// JavaScript in a fresh context. There is no safe-list defence
// here; the rule must fire on any body-tainted first arg.
app.post("/run", (req, res) => {
  vm.runInNewContext(req.body.script);
  res.end();
});

// CASE 4: `vm.runInThisContext` variant — same shape, different
// vm method.
app.post("/run-this", (req, res) => {
  vm.runInThisContext(req.body.script);
  res.end();
});

// CASE 5: bare-ident `unserialize(...)` after destructured
// import — covers the `const { unserialize } = require(...)`
// shape.
import { unserialize } from "node-serialize";
app.post("/import-bare", (req, res) => {
  const obj = unserialize(req.body.payload);
  res.json({ obj });
});
