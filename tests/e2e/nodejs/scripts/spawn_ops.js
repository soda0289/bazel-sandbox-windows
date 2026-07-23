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
// Run as: node spawn_ops.js <execroot>            # parent (absolute-path child)
//         node spawn_ops.js childcwd <out-path>   # child (self re-entry)
//         node spawn_ops.js spawncwdrel <execroot>  # parent (cwd-RELATIVE child)
//         node spawn_ops.js childcwdrel             # child (cwd-relative re-entry)
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

// childcwdrel: like childcwd, but touches files through cwd-RELATIVE names rather
// than absolute paths. Launched from an overlay-only cwd, it writes+reads
// "childrel.txt" (undeclared -> overlay) and reads "..\seedrel.txt" (a REAL
// declared input one level up). The hook-layer reverse-map maps the backing-store
// cwd resolution back to the virtual execroot so both resolve.
function childcwdrel() {
    fs.writeFileSync("childrel.txt", "RELWROTE");
    const wb = fs.readFileSync("childrel.txt", "utf8");
    const ib = fs.readFileSync(p.join("..", "seedrel.txt"), "utf8");
    process.stdout.write("CHILD=OK WROTE=" + wb + " INPUT=" + ib);
}

function spawncwdrel(ws) {
    const d = p.join(ws, "spawnreldir");
    fs.mkdirSync(d);
    const res = cp.spawnSync(process.execPath, [__filename, "childcwdrel"], {
        cwd: d, // lpCurrentDirectory = overlay-only dir
        encoding: "utf8",
    });
    if (res.status !== 0) {
        process.stdout.write("SPAWN=ERR:" + res.status + " OUT=" + (res.stdout || "") + (res.stderr || ""));
        process.exit(1);
    }
    const readback = fs.readFileSync(p.join(d, "childrel.txt"), "utf8");
    process.stdout.write("SPAWN=" + (res.stdout || "").trim() + " READBACK=" + readback);
}

// childstatopen: from an overlay-only cwd, write scratch.bin by RELATIVE name,
// then stat (fs.existsSync + fs.statSync) and open/read (fs.readFileSync) it by
// relative name. All three must agree the file exists. Before the backing-
// reverse-map existence guard the existing backing file's stat reverse-mapped to
// its undeclared virtual path and was masked NOT_FOUND under --filter-inputs
// while the read still resolved to backing (the stat/open desync).
function childstatopen() {
    fs.writeFileSync("scratch.bin", "STATOPEN");
    const exists = fs.existsSync("scratch.bin");
    const size = exists ? fs.statSync("scratch.bin").size : -1;
    const read = fs.readFileSync("scratch.bin", "utf8");
    process.stdout.write("CHILD=OK STAT=" + exists + " SIZE=" + size + " READ=" + read);
}

function spawnstatopen(ws) {
    const d = p.join(ws, "spawnstatdir");
    fs.mkdirSync(d);
    const res = cp.spawnSync(process.execPath, [__filename, "childstatopen"], {
        cwd: d, // lpCurrentDirectory = overlay-only dir
        encoding: "utf8",
    });
    if (res.status !== 0) {
        process.stdout.write("SPAWN=ERR:" + res.status + " OUT=" + (res.stdout || "") + (res.stderr || ""));
        process.exit(1);
    }
    process.stdout.write("SPAWN=" + (res.stdout || "").trim());
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
} else if (arg === "childcwdrel") {
    childcwdrel();
} else if (arg === "childstatopen") {
    childstatopen();
} else if (arg === "spawnstatopen") {
    spawnstatopen(process.argv[3]);
} else if (arg === "spawncwdrel") {
    spawncwdrel(process.argv[3]);
} else {
    spawncwd(arg);
}
