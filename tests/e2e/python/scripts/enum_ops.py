# Stresses the write-overlay's *enumeration splice* through Python's os.scandir
# (CPython's readdir loop -> FindFirstFile/FindNextFile). Enumeration is the
# overlay's hardest area: a single listing of one directory must merge the REAL
# on-disk entries (returned by the underlying FindFirstFile) with the
# OVERLAY-ONLY entries (created this process into the backing store) - without
# duplicates, reflecting the removal of an overlay-created entry - all while the
# real execroot stays byte-for-byte unchanged.
#
# os.scandir is the specific API realtools.ps1's header flags as a historical
# trouble spot for the overlay (a stale last-error / WinError 203 leaking out of
# the merged enumeration), so this lane drives it directly.
#
# NOTE: we only ever create/delete OVERLAY entries here. The overlay is
# backing-store-as-truth with NO whiteout markers (see
# docs/design/detours-write-overlay-vfs.md 6.3.1), so a REAL visible in-cone
# file is immutable: deleting or renaming it is denied in permissive mode. The
# real entries therefore always enumerate through the passthrough unchanged;
# that immutability is what makes the merge (not a mutation) the thing to test.
#
# The test pre-seeds <execroot>/mix on the real disk with realA.txt/realB.txt.
#
# Run as: python enum_ops.py <execroot>
# Emits a space-separated set of markers the test asserts on:
#   LIST1=<entries>     baseline listing of the seeded (real) dir
#   LIST2=<entries>     listing after splicing overlay entries + one deletion
#   GLOBOV=<entries>    merged listing filtered to the "ov" prefix
#   GLOBREAL=<entries>  merged listing filtered to the "real" prefix
#   READOV=<content>    read-back of an overlay-only file
#   READREAL=<content>  passthrough read-back of a real file
import os
import sys


def scan(d):
    with os.scandir(d) as it:
        return sorted(e.name for e in it)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: enum_ops.py <execroot>\n")
        return 2
    ws = sys.argv[1]
    d = os.path.join(ws, "mix")  # pre-seeded on the real disk

    # baseline: the seeded real entries enumerate through the passthrough
    list1 = ",".join(scan(d))

    # splice overlay-only entries (files + a subdir) into the SAME directory
    # that already holds the real entries
    with open(os.path.join(d, "ovX.txt"), "w", encoding="utf-8") as f:
        f.write("OVX")
    with open(os.path.join(d, "ovY.txt"), "w", encoding="utf-8") as f:
        f.write("OVY")
    os.mkdir(os.path.join(d, "ovsub"))
    with open(os.path.join(d, "ovsub", "inner.txt"), "w", encoding="utf-8") as f:
        f.write("INNER")

    # delete one OVERLAY-created entry: it must drop out of the merged view
    # while the real entries (and the other overlay entries) remain
    os.remove(os.path.join(d, "ovY.txt"))

    # merged view: realA/realB + ovX.txt + ovsub, but not ovY.txt
    entries = scan(d)
    list2 = ",".join(entries)

    # prefix filters over the merged set, both halves
    glob_ov = ",".join(n for n in entries if n.startswith("ov"))
    glob_real = ",".join(n for n in entries if n.startswith("real"))

    # read-back: an overlay-only file and a real (passthrough) file
    with open(os.path.join(d, "ovX.txt"), "r", encoding="utf-8") as f:
        read_ov = f.read()
    with open(os.path.join(d, "realA.txt"), "r", encoding="utf-8") as f:
        read_real = f.read()

    sys.stdout.write(
        "LIST1=" + list1
        + " LIST2=" + list2
        + " GLOBOV=" + glob_ov
        + " GLOBREAL=" + glob_real
        + " READOV=" + read_ov
        + " READREAL=" + read_real
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
