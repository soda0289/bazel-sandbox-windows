# Exercises the sandbox's *input-filtering* mode (the mode Bazel uses in
# production) from a real CPython process. Only the declared -r inputs are
# visible; every other real file under the execroot is masked NOT_FOUND and
# hidden from enumeration.
#
# This drives Python's own OS-API paths for both halves of the guarantee:
#   - os.scandir (CPython readdir loop -> FindFirstFile/FindNextFile) must NOT
#     surface the undeclared sibling, and
#   - open() of the undeclared sibling must fail FileNotFoundError (the mask
#     presents it as absent, not access-denied).
#
# The test seeds <execroot>/decl.txt (declared -r) and <execroot>/secret.txt
# (undeclared) before invoking the sandbox with `--filter-inputs ... -r decl.txt`.
#
# Run as: python filter_ops.py <execroot>
# Emits space-separated markers the test asserts on:
#   LIST=<entries>        os.scandir of the execroot (declared visible, undeclared hidden)
#   READDECL=<content>    read-back of the declared input
#   READSECRET=<content|ERR:NotFound|ERR:other>  attempted read of the undeclared file
import os
import sys


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: filter_ops.py <execroot>\n")
        return 2
    ws = sys.argv[1]

    with os.scandir(ws) as it:
        listing = ",".join(sorted(e.name for e in it))

    with open(os.path.join(ws, "decl.txt"), "r", encoding="utf-8") as f:
        read_decl = f.read()

    try:
        with open(os.path.join(ws, "secret.txt"), "r", encoding="utf-8") as f:
            read_secret = f.read()
    except FileNotFoundError:
        read_secret = "ERR:NotFound"
    except OSError:
        read_secret = "ERR:other"

    sys.stdout.write(
        "LIST=" + listing
        + " READDECL=" + read_decl
        + " READSECRET=" + read_secret
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
