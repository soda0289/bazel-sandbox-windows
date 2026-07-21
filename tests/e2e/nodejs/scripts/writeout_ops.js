// Declared-output (-w) write-through under --write-overlay, through Node's fs.
// Writes to a DECLARED OUTPUT path (passed -w by the test) and to an UNDECLARED
// sibling in the same directory, then reads both back. A declared output is NOT
// redirected into the backing store - it writes THROUGH to the real execroot
// (how Bazel collects an action's declared outputs) - while the undeclared
// sibling is redirected into the process-private overlay. Both reads succeed
// in-process (overlay read-after-write covers the redirected sibling); the test
// then asserts real-disk placement: only the -w output lands on disk.
//
// Run as: node writeout_ops.js <declared-out> <undeclared-sibling>
// Emits:  OUT=<content-read-back> SIB=<content-read-back>
"use strict";
const fs = require("fs");

function readOrErr(path) {
    try {
        return fs.readFileSync(path, "utf8");
    } catch (e) {
        return "ERR:NotFound";
    }
}

const out = process.argv[2];
const sibling = process.argv[3];
fs.writeFileSync(out, "DECLARED-OUT");
fs.writeFileSync(sibling, "UNDECLARED-SIB");
process.stdout.write("OUT=" + readOrErr(out) + " SIB=" + readOrErr(sibling));
