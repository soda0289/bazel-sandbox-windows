// Stresses the write-overlay's *enumeration splice* through .NET's directory
// APIs (FindFirstFile/FindNextFile under Directory.GetFileSystemEntries and the
// pattern overload). Enumeration is the overlay's hardest area: a single
// listing of one directory must merge the REAL on-disk entries (returned by the
// underlying FindFirstFile) with the OVERLAY-ONLY entries (created this process
// into the backing store) - without duplicates, honoring wildcard filters, and
// reflecting the removal of an overlay-created entry - all while the real
// execroot stays byte-for-byte unchanged.
//
// NOTE: we only ever create/delete OVERLAY entries here. The overlay is
// backing-store-as-truth with NO whiteout markers (see
// docs/design/detours-write-overlay-vfs.md 6.3.1), so a REAL visible in-cone
// file is immutable: deleting or renaming it is denied in permissive mode. The
// real entries therefore always enumerate through the passthrough unchanged;
// that immutability is what makes the merge (not a mutation) the thing to test.
//
// The test pre-seeds <execroot>/mix on the real disk with realA.txt/realB.txt.
//
// Run as: enum_ops.exe <execroot>
// Emits a space-separated set of markers the test asserts on:
//   LIST1=<entries>     baseline listing of the seeded (real) dir
//   LIST2=<entries>     listing after splicing overlay entries + one deletion
//   GLOBOV=<entries>    GetFileSystemEntries(dir, "ov*") over the merge
//   GLOBREAL=<entries>  ... "real*" over the merge
//   READOV=<content>    read-back of an overlay-only file
//   READREAL=<content>  passthrough read-back of a real file
using System;
using System.IO;
using System.Linq;

internal static class Program {
    private static string List(string dir) {
        return string.Join(
            ",",
            Directory.GetFileSystemEntries(dir)
                .Select(Path.GetFileName)
                .OrderBy(name => name, StringComparer.Ordinal));
    }

    private static string Glob(string dir, string pattern) {
        return string.Join(
            ",",
            Directory.GetFileSystemEntries(dir, pattern)
                .Select(Path.GetFileName)
                .OrderBy(name => name, StringComparer.Ordinal));
    }

    private static int Main(string[] args) {
        if (args.Length < 1) {
            Console.Error.WriteLine("usage: enum_ops.exe <execroot>");
            return 2;
        }
        string ws = args[0];
        string d = Path.Combine(ws, "mix");  // pre-seeded on the real disk

        // baseline: the seeded real entries enumerate through the passthrough
        string list1 = List(d);

        // splice overlay-only entries (files + a subdir) into the SAME directory
        // that already holds the real entries
        File.WriteAllText(Path.Combine(d, "ovX.txt"), "OVX");
        File.WriteAllText(Path.Combine(d, "ovY.txt"), "OVY");
        Directory.CreateDirectory(Path.Combine(d, "ovsub"));
        File.WriteAllText(Path.Combine(d, "ovsub", "inner.txt"), "INNER");

        // delete one OVERLAY-created entry: it must drop out of the merged view
        // while the real entries (and the other overlay entries) remain
        File.Delete(Path.Combine(d, "ovY.txt"));

        // merged view: realA/realB + ovX.txt + ovsub, but not ovY.txt
        string list2 = List(d);

        // wildcard enumeration over the merged set, both halves
        string globOv = Glob(d, "ov*");
        string globReal = Glob(d, "real*");

        // read-back: an overlay-only file and a real (passthrough) file
        string readOv = File.ReadAllText(Path.Combine(d, "ovX.txt"));
        string readReal = File.ReadAllText(Path.Combine(d, "realA.txt"));

        Console.Write(
            "LIST1=" + list1 +
            " LIST2=" + list2 +
            " GLOBOV=" + globOv +
            " GLOBREAL=" + globReal +
            " READOV=" + readOv +
            " READREAL=" + readReal);
        return 0;
    }
}
