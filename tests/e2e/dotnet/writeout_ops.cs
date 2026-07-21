// Declared-output (-w) write-through under --write-overlay, through System.IO.
// Writes to a DECLARED OUTPUT path (passed -w by the test) and to an UNDECLARED
// sibling in the same directory, then reads both back. A declared output is NOT
// redirected into the backing store - it writes THROUGH to the real execroot
// (how Bazel collects an action's declared outputs) - while the undeclared
// sibling is redirected into the process-private overlay. Both reads succeed
// in-process (overlay read-after-write covers the redirected sibling); the test
// then asserts real-disk placement: only the -w output lands on disk.
//
// Run as: writeout_ops <declared-out> <undeclared-sibling>
// Emits:  OUT=<content-read-back> SIB=<content-read-back>
using System;
using System.IO;

internal static class Program {
    private static string ReadOrErr(string path) {
        try {
            return File.ReadAllText(path);
        } catch (FileNotFoundException) {
            return "ERR:NotFound";
        } catch (DirectoryNotFoundException) {
            return "ERR:NotFound";
        }
    }

    private static int Main(string[] args) {
        if (args.Length < 2) {
            Console.Error.WriteLine("usage: writeout_ops <declared-out> <undeclared-sibling>");
            return 2;
        }
        string outPath = args[0];
        string sibling = args[1];
        File.WriteAllText(outPath, "DECLARED-OUT");
        File.WriteAllText(sibling, "UNDECLARED-SIB");
        Console.Write("OUT=" + ReadOrErr(outPath) + " SIB=" + ReadOrErr(sibling));
        return 0;
    }
}
