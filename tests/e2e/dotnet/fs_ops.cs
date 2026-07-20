// Exercises the full set of .NET file-system mutation ops through the
// write-overlay in a single --write-overlay invocation: write, read-back,
// rename, move (into a subdir), delete. Each mutation must be visible to
// subsequent ops within the same invocation (overlay read-after-write +
// enumeration splice), and none of it may touch the real execroot.
//
// This is the .NET analogue of tests/e2e/nodejs/scripts/fs_ops.js: it drives
// the same read/write/move/rename/delete sequence, but through System.IO
// (CreateFileW / MoveFileEx / DeleteFile / FindFirstFile under the hood) so the
// overlay is validated against the .NET runtime's OS-API patterns.
//
// Run as: fs_ops.exe <execroot>
// Emits a space-separated set of markers the test asserts on:
//   READ=<content>            content read back after write
//   AFTERRENAME=<entries>     dir listing after renaming a.txt -> b.txt
//   AFTERDELETE=<entries>     dir listing after creating+deleting c.txt
//   MOVED=<content>           content read back after moving b.txt into sub/
using System;
using System.IO;
using System.Linq;

internal static class Program {
    private static string ListDir(string dir) {
        return string.Join(
            ",",
            Directory.GetFileSystemEntries(dir)
                .Select(Path.GetFileName)
                .OrderBy(name => name, StringComparer.Ordinal));
    }

    private static int Main(string[] args) {
        if (args.Length < 1) {
            Console.Error.WriteLine("usage: fs_ops.exe <execroot>");
            return 2;
        }
        string ws = args[0];
        string d = Path.Combine(ws, "wd");
        Directory.CreateDirectory(d);

        // write + read-back
        string a = Path.Combine(d, "a.txt");
        File.WriteAllText(a, "OVNET");
        string read = File.ReadAllText(a);

        // rename a.txt -> b.txt (same dir); the listing must show b.txt, not a.txt
        string b = Path.Combine(d, "b.txt");
        File.Move(a, b);
        string afterRename = ListDir(d);

        // create then delete c.txt; the listing must no longer contain c.txt
        string c = Path.Combine(d, "c.txt");
        File.WriteAllText(c, "TMP");
        File.Delete(c);
        string afterDelete = ListDir(d);

        // move b.txt into a freshly created subdirectory, then read it back there
        string sub = Path.Combine(d, "sub");
        Directory.CreateDirectory(sub);
        string moved = Path.Combine(sub, "b.txt");
        File.Move(b, moved);
        string movedContent = File.ReadAllText(moved);

        Console.Write(
            "READ=" + read +
            " AFTERRENAME=" + afterRename +
            " AFTERDELETE=" + afterDelete +
            " MOVED=" + movedContent);
        return 0;
    }
}
