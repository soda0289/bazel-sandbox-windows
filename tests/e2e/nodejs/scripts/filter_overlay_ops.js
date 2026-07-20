// Exercises the COMBINED input-filtering + write-overlay mode from a real Node.js
// process: `--filter-inputs --write-overlay` with NO declared -r inputs, so the
// seeded real <execroot>\secret.txt is a HIDDEN undeclared input (masked ENOENT).
// A tool output whose name collides with that hidden input must land in the
// overlay, and mutating that overlay copy must never re-reveal the real file.
//
// One op per invocation (the caller re-seeds a fresh secret.txt each time):
//   node filter_overlay_ops.js <execroot> <op>
//
// Ops and the markers the test asserts on:
//   create           create over the hidden name -> CREATE=<content read back>
//   renameonto       write tmp then rename it ONTO the hidden name ->
//                    RENAMEONTO=<content read back>
//   renameaway       create over the hidden name then rename it AWAY ->
//                    RENAMEAWAY=<moved content> SRCAFTER=<orig read; ERR:ENOENT>
//   delete           create over the hidden name then delete it ->
//                    AFTERDEL=<orig read; ERR:ENOENT>
//   deletebare       delete the hidden name with NO overlay copy ->
//                    DELETEBARE=<OK|ERR:ENOENT|ERR:other>  (ENOENT no-op)
//   renamefrombare   rename the hidden name away with NO overlay copy ->
//                    RENAMEFROMBARE=<OK|ERR:ENOENT|ERR:other>  (ENOENT no-op)
//
// fs.renameSync/fs.rmSync take the path-based MoveFileEx/DeleteFile hooks. The
// read-back after delete / rename-away MUST be ERR:ENOENT: once the overlay copy
// is gone the masked real input must not resurface.
"use strict";
const fs = require("fs");
const p = require("path");

function read(path) {
    try {
        return fs.readFileSync(path, "utf8");
    } catch (e) {
        return e.code === "ENOENT" ? "ERR:ENOENT" : "ERR:other";
    }
}

function classify(fn) {
    try {
        fn();
        return "OK";
    } catch (e) {
        return e.code === "ENOENT" ? "ERR:ENOENT" : "ERR:other";
    }
}

const ws = process.argv[2];
const op = process.argv[3];
const secret = p.join(ws, "secret.txt");
const tmp = p.join(ws, "tmp.txt");
const moved = p.join(ws, "moved.txt");

let out;
switch (op) {
    case "create":
        fs.writeFileSync(secret, "OVERLAY-NEW");
        out = "CREATE=" + read(secret);
        break;
    case "renameonto":
        fs.writeFileSync(tmp, "OVERLAY-ONTO");
        fs.renameSync(tmp, secret);
        out = "RENAMEONTO=" + read(secret);
        break;
    case "renameaway":
        fs.writeFileSync(secret, "OVERLAY-AWAY");
        fs.renameSync(secret, moved);
        out = "RENAMEAWAY=" + read(moved) + " SRCAFTER=" + read(secret);
        break;
    case "delete":
        fs.writeFileSync(secret, "OVERLAY-DEL");
        fs.rmSync(secret);
        out = "AFTERDEL=" + read(secret);
        break;
    case "deletebare":
        out = "DELETEBARE=" + classify(() => fs.rmSync(secret));
        break;
    case "renamefrombare":
        out = "RENAMEFROMBARE=" + classify(() => fs.renameSync(secret, moved));
        break;
    default:
        process.stderr.write("unknown op: " + op + "\n");
        process.exit(2);
}
process.stdout.write(out);
