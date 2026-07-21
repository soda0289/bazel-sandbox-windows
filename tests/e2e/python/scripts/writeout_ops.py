# Declared-output (-w) write-through under --write-overlay, through CPython.
# Writes to a DECLARED OUTPUT path (passed -w by the test) and to an UNDECLARED
# sibling in the same directory, then reads both back. A declared output is NOT
# redirected into the backing store - it writes THROUGH to the real execroot
# (how Bazel collects an action's declared outputs) - while the undeclared
# sibling is redirected into the process-private overlay. Both reads succeed
# in-process (overlay read-after-write covers the redirected sibling); the test
# then asserts real-disk placement: only the -w output lands on disk.
#
# Run as: python writeout_ops.py <declared-out> <undeclared-sibling>
# Emits:  OUT=<content-read-back> SIB=<content-read-back>
import sys


def read_or_err(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "ERR:NotFound"


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: writeout_ops.py <declared-out> <undeclared-sibling>\n")
        return 2
    out, sibling = sys.argv[1], sys.argv[2]
    with open(out, "w", encoding="utf-8") as f:
        f.write("DECLARED-OUT")
    with open(sibling, "w", encoding="utf-8") as f:
        f.write("UNDECLARED-SIB")
    sys.stdout.write("OUT=%s SIB=%s" % (read_or_err(out), read_or_err(sibling)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
