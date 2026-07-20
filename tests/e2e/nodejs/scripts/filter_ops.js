// Exercises the sandbox's *input-filtering* mode (the mode Bazel uses in
// production) from a real Node.js process. Only the declared -r inputs are
// visible; every other real file under the execroot is masked NOT_FOUND and
// hidden from enumeration.
//
// This drives node's own OS-API paths for both halves of the guarantee:
//   - fs.readdirSync (-> FindFirstFile/FindNextFile) must NOT surface the
//     undeclared sibling, and
//   - fs.readFileSync of the undeclared sibling must fail ENOENT (the mask
//     presents it as absent, not access-denied).
//
// The test seeds <execroot>/decl.txt (declared -r) and <execroot>/secret.txt
// (undeclared) before invoking the sandbox with `--filter-inputs ... -r decl.txt`.
//
// Run as: node filter_ops.js <execroot>
// Emits space-separated markers the test asserts on:
//   LIST=<entries>        readdir of the execroot (declared visible, undeclared hidden)
//   READDECL=<content>    read-back of the declared input
//   READSECRET=<content|ERR:ENOENT|ERR:other>  attempted read of the undeclared file
"use strict";
const fs = require("fs");
const p = require("path");

const ws = process.argv[2];

const listing = fs.readdirSync(ws).sort().join(",");
const readDecl = fs.readFileSync(p.join(ws, "decl.txt"), "utf8");

let readSecret;
try {
    readSecret = fs.readFileSync(p.join(ws, "secret.txt"), "utf8");
} catch (e) {
    readSecret = e.code === "ENOENT" ? "ERR:ENOENT" : "ERR:other";
}

process.stdout.write(
    "LIST=" + listing +
    " READDECL=" + readDecl +
    " READSECRET=" + readSecret
);
