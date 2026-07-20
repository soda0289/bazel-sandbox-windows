// node fs read-after-write + enumeration splice, all in one --write-overlay
// invocation (the overlay backing store is per invocation).
//
// Run as: node fs_readback.js <execroot>
// Emits:  LIST=<sorted dir entries> READ=<content of the copied file>
"use strict";
const fs = require("fs");
const p = require("path");

const ws = process.argv[2];
const d = p.join(ws, "wd");
fs.mkdirSync(d);

const src = p.join(d, "in.txt");
fs.writeFileSync(src, "OVNODE");

const list = fs.readdirSync(d).sort().join(",");

const dst = p.join(d, "out.txt");
fs.copyFileSync(src, dst);

process.stdout.write("LIST=" + list + " READ=" + fs.readFileSync(dst, "utf8"));
