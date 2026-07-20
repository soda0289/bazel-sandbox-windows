// Copies a real in-cone input into an overlay directory with File.Copy, then
// reads the copy back and lists the directory. File.Copy maps to the Win32
// CopyFile / CopyFileEx kernel-copy path (the runtime opens the source and
// creates the destination itself), so the overlay must intercept those opens
// and redirect the write into the backing store - a leak would land out.txt on
// the real execroot. This covers the CopyFile family (`File.Copy`) separately
// from fs_ops.cs's File.Move.
//
// Run as: copy_ops.exe <execroot>
// Emits:
//   READ=<content>   content read back from the copied file
//   LIST=<entries>   directory listing of the overlay directory
using System;
using System.IO;
using System.Linq;

internal static class Program {
    private static int Main(string[] args) {
        if (args.Length < 1) {
            Console.Error.WriteLine("usage: copy_ops.exe <execroot>");
            return 2;
        }
        string ws = args[0];

        string src = Path.Combine(ws, "in.txt");  // real, in-cone input (allowed read)
        File.WriteAllText(src, "OVNETCOPY");

        string d = Path.Combine(ws, "wd");
        Directory.CreateDirectory(d);
        string dst = Path.Combine(d, "out.txt");
        File.Copy(src, dst);

        string read = File.ReadAllText(dst);
        string listing = string.Join(
            ",",
            Directory.GetFileSystemEntries(d)
                .Select(Path.GetFileName)
                .OrderBy(name => name, StringComparer.Ordinal));

        Console.Write("READ=" + read + " LIST=" + listing);
        return 0;
    }
}
