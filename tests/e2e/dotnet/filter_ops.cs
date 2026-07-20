// Exercises the sandbox's *input-filtering* mode (the mode Bazel uses in
// production) from a real .NET process. Only the declared -r inputs are visible;
// every other real file under the execroot is masked NOT_FOUND and hidden from
// enumeration.
//
// This drives .NET's own OS-API paths for both halves of the guarantee:
//   - Directory.GetFileSystemEntries (-> FindFirstFile/FindNextFile) must NOT
//     surface the undeclared sibling, and
//   - File.ReadAllText of the undeclared sibling must throw
//     FileNotFoundException (the mask presents it as absent, not access-denied).
//
// The test seeds <execroot>/decl.txt (declared -r) and <execroot>/secret.txt
// (undeclared) before invoking the sandbox with `--filter-inputs ... -r decl.txt`.
//
// Run as: filter_ops.exe <execroot>
// Emits space-separated markers the test asserts on:
//   LIST=<entries>        listing of the execroot (declared visible, undeclared hidden)
//   READDECL=<content>    read-back of the declared input
//   READSECRET=<content|ERR:NotFound|ERR:other>  attempted read of the undeclared file
using System;
using System.IO;
using System.Linq;

internal static class Program {
    private static int Main(string[] args) {
        if (args.Length < 1) {
            Console.Error.WriteLine("usage: filter_ops.exe <execroot>");
            return 2;
        }
        string ws = args[0];

        string listing = string.Join(
            ",",
            Directory.GetFileSystemEntries(ws)
                .Select(Path.GetFileName)
                .OrderBy(name => name, StringComparer.Ordinal));

        string readDecl = File.ReadAllText(Path.Combine(ws, "decl.txt"));

        string readSecret;
        try {
            readSecret = File.ReadAllText(Path.Combine(ws, "secret.txt"));
        } catch (FileNotFoundException) {
            readSecret = "ERR:NotFound";
        } catch (DirectoryNotFoundException) {
            readSecret = "ERR:NotFound";
        } catch (IOException) {
            readSecret = "ERR:other";
        }

        Console.Write(
            "LIST=" + listing +
            " READDECL=" + readDecl +
            " READSECRET=" + readSecret);
        return 0;
    }
}
