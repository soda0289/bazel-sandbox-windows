# Exercises the full set of Python fs mutation ops through the write-overlay in
# a single --write-overlay invocation: write, read-back, rename, move (into a
# subdir), delete. Each mutation must be visible to subsequent ops within the
# same invocation (overlay read-after-write + enumeration splice), and none of
# it may touch the real execroot.
#
# Directory listings deliberately go through os.scandir (CPython's readdir loop
# -> FindFirstFile/FindNextFile), the API the overlay's enumeration splice has
# to satisfy and the one realtools.ps1 calls out as a historical trouble spot
# (a stale last-error / WinError 203 leaking out of the merged enumeration).
#
# Run as: python fs_ops.py <execroot>
# Emits a space-separated set of markers the test asserts on:
#   READ=<content>            content read back after write
#   AFTERRENAME=<entries>     dir listing after renaming a.txt -> b.txt
#   AFTERDELETE=<entries>     dir listing after creating+deleting c.txt
#   MOVED=<content>           content read back after moving b.txt into sub/
import os
import sys


def listing(d):
    with os.scandir(d) as it:
        names = sorted(e.name for e in it)
    return ",".join(names)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: fs_ops.py <execroot>\n")
        return 2
    ws = sys.argv[1]
    d = os.path.join(ws, "wd")
    os.makedirs(d, exist_ok=True)

    # write + read-back
    a = os.path.join(d, "a.txt")
    with open(a, "w", encoding="utf-8") as f:
        f.write("OVOPS")
    with open(a, "r", encoding="utf-8") as f:
        read = f.read()

    # rename a.txt -> b.txt (same dir); the listing must show b.txt, not a.txt
    b = os.path.join(d, "b.txt")
    os.replace(a, b)
    after_rename = listing(d)

    # create then delete c.txt; the listing must no longer contain c.txt
    c = os.path.join(d, "c.txt")
    with open(c, "w", encoding="utf-8") as f:
        f.write("TMP")
    os.remove(c)
    after_delete = listing(d)

    # move b.txt into a freshly created subdirectory, then read it back there
    sub = os.path.join(d, "sub")
    os.mkdir(sub)
    moved = os.path.join(sub, "b.txt")
    os.replace(b, moved)
    with open(moved, "r", encoding="utf-8") as f:
        moved_content = f.read()

    sys.stdout.write(
        "READ=" + read
        + " AFTERRENAME=" + after_rename
        + " AFTERDELETE=" + after_delete
        + " MOVED=" + moved_content
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
