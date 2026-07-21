// The rules_go GoStdlib regression, through .NET's Process API (the Python/Node/
// Java analogue of GoSpawnOverlayOnlyCwd). Creates a directory that exists ONLY
// in the overlay backing store, then launches a child (this same csharp_binary,
// re-entered via `childcwd`) with that overlay-only dir as its working directory
// (ProcessStartInfo.WorkingDirectory -> CreateProcessW lpCurrentDirectory,
// WITHOUT any preceding SetCurrentDirectory). Without the CreateProcess
// working-directory overlay redirect the child fails to launch (ERROR_DIRECTORY
// 267); with it the child launches from the concrete backing dir and writes its
// output (an absolute path under the virtual execroot) into the overlay, which
// the parent reads back. The real execroot stays untouched.
//
// Run as: spawn_ops spawncwd <execroot> <cmd.exe> <self-launcher.bat>  # parent
//         spawn_ops childcwd <out-path>                                # child
// Parent emits:  SPAWN=<child-stdout> READBACK=<content-read-through-overlay>
// Child emits:   CHILD=OK
using System;
using System.Diagnostics;
using System.IO;

internal static class Program {
    private static int ChildCwd(string outPath) {
        File.WriteAllText(outPath, "CHILDWROTE");
        Console.Write("CHILD=OK");
        return 0;
    }

    private static int Main(string[] args) {
        if (args.Length < 2) {
            Console.Error.WriteLine("usage: spawn_ops spawncwd <execroot> <cmd> <self> | childcwd <out>");
            return 2;
        }
        if (args[0] == "childcwd") {
            return ChildCwd(args[1]);
        }
        // parent: spawncwd <execroot> <cmd.exe> <self-launcher.bat>
        string ws = args[1];
        string cmdExe = args[2];
        string self = args[3];
        string d = Path.Combine(ws, "spawndir");
        Directory.CreateDirectory(d);
        string outPath = Path.Combine(d, "childfile.txt");

        // The csharp_binary launcher is a .bat, so re-enter it via cmd /c. The
        // overlay-only working directory is what exercises the redirect.
        var psi = new ProcessStartInfo {
            FileName = cmdExe,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = d,  // lpCurrentDirectory = overlay-only dir
        };
        psi.ArgumentList.Add("/c");
        psi.ArgumentList.Add(self);
        psi.ArgumentList.Add("childcwd");
        psi.ArgumentList.Add(outPath);

        var p = Process.Start(psi);
        string childOut = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) {
            Console.Write("SPAWN=ERR:" + p.ExitCode + " OUT=" + childOut);
            return 1;
        }
        string readback = File.ReadAllText(outPath);
        Console.Write("SPAWN=" + childOut.Trim() + " READBACK=" + readback);
        return 0;
    }
}
