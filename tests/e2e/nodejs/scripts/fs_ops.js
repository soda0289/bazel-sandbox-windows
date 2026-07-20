// Exercises the full set of node fs mutation ops through the write-overlay in a
// single --write-overlay invocation: write, read-back, rename, move (into a
// subdir), delete. Each mutation must be visible to subsequent ops within the
// same invocation (overlay read-after-write + enumeration splice), and none of
// it may touch the real execroot.
//
// Run as: node fs_ops.js <execroot>
// Emits a space-separated set of markers the test asserts on:
//   READ=<content>            content read back after write
//   AFTERRENAME=<entries>     dir listing after renaming a.txt -> b.txt
//   AFTERDELETE=<entries>     dir listing after creating+deleting c.txt
//   MOVED=<content>           content read back after moving b.txt into sub/
"use strict";
const fs = require("fs");
const p = require("path");

const ws = process.argv[2];
const d = p.join(ws, "wd");
fs.mkdirSync(d, { recursive: true });

// write + read-back
const a = p.join(d, "a.txt");
fs.writeFileSync(a, "OVOPS");
const read = fs.readFileSync(a, "utf8");

// rename a.txt -> b.txt (same dir); the listing must show b.txt, not a.txt
const b = p.join(d, "b.txt");
fs.renameSync(a, b);
const afterRename = fs.readdirSync(d).sort().join(",");

// create then delete c.txt; the listing must no longer contain c.txt
const c = p.join(d, "c.txt");
fs.writeFileSync(c, "TMP");
fs.rmSync(c);
const afterDelete = fs.readdirSync(d).sort().join(",");

// move b.txt into a freshly created subdirectory, then read it back there
const sub = p.join(d, "sub");
fs.mkdirSync(sub);
const moved = p.join(sub, "b.txt");
fs.renameSync(b, moved);
const movedContent = fs.readFileSync(moved, "utf8");

process.stdout.write(
    "READ=" + read +
    " AFTERRENAME=" + afterRename +
    " AFTERDELETE=" + afterDelete +
    " MOVED=" + movedContent
);
