# The rules_go GoStdlib regression, through CPython. Creates a directory that
# exists ONLY in the overlay backing store, then subprocess-spawns a child
# (this same script, re-entered via `childcwd`) with that overlay-only dir as
# its working directory (subprocess cwd= -> CreateProcessW lpCurrentDirectory,
# WITHOUT any preceding SetCurrentDirectory). Without the CreateProcess
# working-directory overlay redirect the OS cannot resolve the absent real dir
# and the child fails to launch (WinError 267, ERROR_DIRECTORY); with it the
# child launches from the concrete backing dir and writes its output (an
# absolute path under the virtual execroot) into the overlay, which the parent
# reads back. The real execroot stays untouched.
#
# Run as: python spawn_ops.py <execroot>            # parent (absolute-path child)
#         python spawn_ops.py childcwd <out-path>   # child (self re-entry)
#         python spawn_ops.py spawncwdrel <execroot>  # parent (cwd-RELATIVE child)
#         python spawn_ops.py childcwdrel             # child (cwd-relative re-entry)
# Parent emits:  SPAWN=<child-stdout> READBACK=<content-read-through-overlay>
# Child emits:   CHILD=OK
import os
import subprocess
import sys


def childcwd(out):
    with open(out, "w", encoding="utf-8") as f:
        f.write("CHILDWROTE")
    sys.stdout.write("CHILD=OK")
    return 0


# childcwdrel: like childcwd, but touches files through cwd-RELATIVE names rather
# than absolute paths. Launched from an overlay-only cwd, it writes+reads
# "childrel.txt" (undeclared -> overlay) and reads "..\seedrel.txt" (a REAL
# declared input one level up). CPython's open() passes the relative path straight
# to CreateFileW, so ntdll joins it against the backing-store cwd; the hook-layer
# reverse-map must map that back to the virtual execroot for both to resolve.
def childcwdrel():
    with open("childrel.txt", "w", encoding="utf-8") as f:
        f.write("RELWROTE")
    with open("childrel.txt", "r", encoding="utf-8") as f:
        wb = f.read()
    with open(os.path.join("..", "seedrel.txt"), "r", encoding="utf-8") as f:
        ib = f.read()
    sys.stdout.write("CHILD=OK WROTE=%s INPUT=%s" % (wb, ib))
    return 0


def spawncwdrel(ws):
    d = os.path.join(ws, "spawnreldir")
    os.mkdir(d)
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "childcwdrel"],
        cwd=d,  # lpCurrentDirectory = overlay-only dir
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stdout.write("SPAWN=ERR:%d OUT=%s" % (proc.returncode, proc.stdout + proc.stderr))
        return 1
    with open(os.path.join(d, "childrel.txt"), "r", encoding="utf-8") as f:
        readback = f.read()
    sys.stdout.write("SPAWN=%s READBACK=%s" % (proc.stdout.strip(), readback))
    return 0


# childstatopen: from an overlay-only cwd, write a scratch file by relative name,
# then STAT it (os.stat -> GetFileAttributes) and OPEN it (open() -> CreateFileW).
# Under --filter-inputs the existing backing file's stat must NOT reverse-map to a
# masked virtual path while the open still resolves to backing (the embedded-JDK
# stat/open desync). Emits STAT / SIZE / READ so the parent can assert agreement.
def childstatopen():
    with open("scratch.bin", "w", encoding="utf-8") as f:
        f.write("STATOPEN")
    exists = os.path.exists("scratch.bin")
    size = os.stat("scratch.bin").st_size if exists else -1
    with open("scratch.bin", "r", encoding="utf-8") as f:
        read = f.read()
    sys.stdout.write("CHILD=OK STAT=%s SIZE=%d READ=%s" % (exists, size, read))
    return 0


def spawnstatopen(ws):
    d = os.path.join(ws, "spawnstatdir")
    os.mkdir(d)
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "childstatopen"],
        cwd=d,  # lpCurrentDirectory = overlay-only dir
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stdout.write("SPAWN=ERR:%d OUT=%s" % (proc.returncode, proc.stdout + proc.stderr))
        return 1
    sys.stdout.write("SPAWN=%s" % proc.stdout.strip())
    return 0


def spawncwd(ws):
    d = os.path.join(ws, "spawndir")
    os.mkdir(d)
    out = os.path.join(d, "childfile.txt")
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "childcwd", out],
        cwd=d,  # lpCurrentDirectory = overlay-only dir
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stdout.write("SPAWN=ERR:%d OUT=%s" % (proc.returncode, proc.stdout + proc.stderr))
        return 1
    with open(out, "r", encoding="utf-8") as f:
        readback = f.read()
    sys.stdout.write("SPAWN=%s READBACK=%s" % (proc.stdout.strip(), readback))
    return 0


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: spawn_ops.py <execroot> | childcwd <out>\n")
        return 2
    if sys.argv[1] == "childcwd":
        if len(sys.argv) < 3:
            sys.stderr.write("usage: spawn_ops.py childcwd <out>\n")
            return 2
        return childcwd(sys.argv[2])
    if sys.argv[1] == "childcwdrel":
        return childcwdrel()
    if sys.argv[1] == "childstatopen":
        return childstatopen()
    if sys.argv[1] == "spawncwdrel":
        if len(sys.argv) < 3:
            sys.stderr.write("usage: spawn_ops.py spawncwdrel <execroot>\n")
            return 2
        return spawncwdrel(sys.argv[2])
    if sys.argv[1] == "spawnstatopen":
        if len(sys.argv) < 3:
            sys.stderr.write("usage: spawn_ops.py spawnstatopen <execroot>\n")
            return 2
        return spawnstatopen(sys.argv[2])
    return spawncwd(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
