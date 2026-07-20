# Exercises the COMBINED input-filtering + write-overlay mode from a real CPython
# process: `--filter-inputs --write-overlay` with NO declared -r inputs, so the
# seeded real <execroot>\secret.txt is a HIDDEN undeclared input (masked
# NOT_FOUND). A tool output whose name collides with that hidden input must land
# in the overlay, and mutating that overlay copy must never re-reveal the real
# file - the hermeticity property whose leak this suite regression-guards.
#
# One op per invocation (the caller re-seeds a fresh secret.txt each time):
#   python filter_overlay_ops.py <execroot> <op>
#
# Ops and the markers the test asserts on:
#   create           create over the hidden name -> CREATE=<content read back>
#   renameonto       write tmp then rename it ONTO the hidden name ->
#                    RENAMEONTO=<content read back>
#   renameaway       create over the hidden name then rename it AWAY ->
#                    RENAMEAWAY=<moved content> SRCAFTER=<orig read; ERR:NotFound>
#   delete           create over the hidden name then delete it ->
#                    AFTERDEL=<orig read; ERR:NotFound>
#   deletebare       delete the hidden name with NO overlay copy ->
#                    DELETEBARE=<OK|ERR:NotFound|ERR:other>  (NOT_FOUND no-op)
#   renamefrombare   rename the hidden name away with NO overlay copy ->
#                    RENAMEFROMBARE=<OK|ERR:NotFound|ERR:other>  (NOT_FOUND no-op)
#
# The read-back after delete / rename-away MUST be ERR:NotFound: once the overlay
# copy is gone the masked real input must not resurface (its bytes must never be
# observed as CREATE/RENAMEAWAY content either).
import os
import sys


def _read(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "ERR:NotFound"
    except OSError:
        return "ERR:other"


def _classify(fn):
    try:
        fn()
        return "OK"
    except FileNotFoundError:
        return "ERR:NotFound"
    except OSError:
        return "ERR:other"


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: filter_overlay_ops.py <execroot> <op>\n")
        return 2
    ws, op = sys.argv[1], sys.argv[2]
    secret = os.path.join(ws, "secret.txt")
    tmp = os.path.join(ws, "tmp.txt")
    moved = os.path.join(ws, "moved.txt")

    def write(path, content):
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    if op == "create":
        write(secret, "OVERLAY-NEW")
        sys.stdout.write("CREATE=" + _read(secret))
    elif op == "renameonto":
        write(tmp, "OVERLAY-ONTO")
        os.replace(tmp, secret)
        sys.stdout.write("RENAMEONTO=" + _read(secret))
    elif op == "renameaway":
        write(secret, "OVERLAY-AWAY")
        os.replace(secret, moved)
        sys.stdout.write("RENAMEAWAY=" + _read(moved) + " SRCAFTER=" + _read(secret))
    elif op == "delete":
        write(secret, "OVERLAY-DEL")
        os.remove(secret)
        sys.stdout.write("AFTERDEL=" + _read(secret))
    elif op == "deletebare":
        sys.stdout.write("DELETEBARE=" + _classify(lambda: os.remove(secret)))
    elif op == "renamefrombare":
        sys.stdout.write("RENAMEFROMBARE=" + _classify(lambda: os.replace(secret, moved)))
    else:
        sys.stderr.write("unknown op: " + op + "\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
