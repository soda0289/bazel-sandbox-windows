// The rules_go GoStdlib regression, through Node's child_process (the Python/
// Java/.NET analogue of GoSpawnOverlayOnlyCwd). Creates a directory that exists
// ONLY in the overlay backing store, then spawns a child (this same script,
// re-entered via `childcwd`) with that overlay-only dir as its working directory
// (spawnSync cwd -> CreateProcessW lpCurrentDirectory, WITHOUT any preceding
// SetCurrentDirectory). Without the CreateProcess working-directory overlay
// redirect the child fails to launch (ERROR_DIRECTORY 267); with it the child
// launches from the concrete backing dir and writes its output (an absolute
// path under the virtual execroot) into the overlay, which the parent reads
// back. The real execroot stays untouched.
//
// Run as: node spawn_ops.js <execroot>            # parent
//         node spawn_ops.js childcwd <out-path>   # child (self re-entry)
// Parent emits:  SPAWN=<child-stdout> READBACK=<content-read-through-overlay>
// Child emits:   CHILD=OK
"use strict";
const fs = require("fs");
const p = require("path");
const cp = require("child_process");

function childcwd(out) {
    fs.writeFileSync(out, "CHILDWROTE");
    process.stdout.write("CHILD=OK");
}

function spawncwd(ws) {
    const d = p.join(ws, "spawndir");
    fs.mkdirSync(d);
    const out = p.join(d, "childfile.txt");
    const res = cp.spawnSync(process.execPath, [__filename, "childcwd", out], {
        cwd: d, // lpCurrentDirectory = overlay-only dir
        encoding: "utf8",
    });
    if (res.status !== 0) {
        process.stdout.write("SPAWN=ERR:" + res.status + " OUT=" + (res.stdout || "") + (res.stderr || ""));
        process.exit(1);
    }
    const readback = fs.readFileSync(out, "utf8");
    process.stdout.write("SPAWN=" + (res.stdout || "").trim() + " READBACK=" + readback);
}

const arg = process.argv[2];
if (arg === "childcwd") {
    childcwd(process.argv[3]);
} else {
    spawncwd(arg);
}
