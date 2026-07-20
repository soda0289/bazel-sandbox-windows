# Copies a real in-cone input into an overlay directory with shutil.copy, then
# reads the copy back and lists the directory - the overlay must intercept the
# source read and redirect the destination write into the backing store (a leak
# would land out.txt on the real execroot).
#
# shutil.copy is the stdlib file-copy tool; on CPython it
# opens the source, creates the destination, and copies the bytes (plus a
# copymode chmod on the destination), so it drives read-after-write on the copy
# and an enumeration splice on the overlay directory in one shot.
#
# Run as: python copy_ops.py <execroot>
# Emits:
#   READ=<content>     content read back from the copied file
#   LIST=<entries>     os.scandir listing of the overlay directory
import os
import shutil
import sys


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: copy_ops.py <execroot>\n")
        return 2
    ws = sys.argv[1]

    src = os.path.join(ws, "in.txt")  # real, in-cone input (allowed read)
    with open(src, "w", encoding="utf-8") as f:
        f.write("OVPYCOPY")

    d = os.path.join(ws, "wd")
    os.makedirs(d, exist_ok=True)
    dst = os.path.join(d, "out.txt")
    shutil.copy(src, dst)

    with open(dst, "r", encoding="utf-8") as f:
        read = f.read()
    with os.scandir(d) as it:
        listing = ",".join(sorted(e.name for e in it))

    sys.stdout.write("READ=" + read + " LIST=" + listing)
    return 0


if __name__ == "__main__":
    sys.exit(main())
