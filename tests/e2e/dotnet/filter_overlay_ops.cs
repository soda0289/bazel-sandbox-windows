// Exercises the COMBINED input-filtering + write-overlay mode from a real .NET
// process: `--filter-inputs --write-overlay` with NO declared -r inputs, so the
// seeded real <execroot>\secret.txt is a HIDDEN undeclared input (masked
// NOT_FOUND). A tool output whose name collides with that hidden input must land
// in the overlay, and mutating that overlay copy must never re-reveal the real
// file.
//
// One op per invocation (the caller re-seeds a fresh secret.txt each time):
//   filter_overlay_ops.exe <execroot> <op>
//
// Ops and the markers the test asserts on:
//   create           create over the hidden name -> CREATE=<content read back>
//   renameonto       write tmp then File.Move it ONTO the hidden name ->
//                    RENAMEONTO=<content read back>
//   renameaway       create over the hidden name then File.Move it AWAY ->
//                    RENAMEAWAY=<moved content> SRCAFTER=<orig read; ERR:NotFound>
//   delete           create over the hidden name then File.Delete it ->
//                    AFTERDEL=<orig read; ERR:NotFound>
//   deletebare       File.Delete the hidden name with NO overlay copy ->
//                    DELETEBARE=<OK|ERR:NotFound|ERR:other>. NOTE: .NET File.Delete
//                    silently succeeds on a not-found path, so OK is expected here;
//                    the hard invariant is the real file staying unchanged.
//   renamefrombare   File.Move the hidden name away with NO overlay copy ->
//                    RENAMEFROMBARE=<OK|ERR:NotFound|ERR:other>  (NOT_FOUND no-op)
//
// File.Move/File.Delete take the path-based MoveFileEx/DeleteFile hooks. The
// read-back after delete / rename-away MUST be ERR:NotFound: once the overlay copy
// is gone the masked real input must not resurface.
using System;
using System.IO;

internal static class Program {
    private static string Read(string path) {
        try {
            return File.ReadAllText(path);
        } catch (FileNotFoundException) {
            return "ERR:NotFound";
        } catch (DirectoryNotFoundException) {
            return "ERR:NotFound";
        } catch (IOException) {
            return "ERR:other";
        }
    }

    private static string Classify(Action fn) {
        try {
            fn();
            return "OK";
        } catch (FileNotFoundException) {
            return "ERR:NotFound";
        } catch (DirectoryNotFoundException) {
            return "ERR:NotFound";
        } catch (IOException) {
            return "ERR:other";
        }
    }

    private static int Main(string[] args) {
        if (args.Length < 2) {
            Console.Error.WriteLine("usage: filter_overlay_ops.exe <execroot> <op>");
            return 2;
        }
        string ws = args[0], op = args[1];
        string secret = Path.Combine(ws, "secret.txt");
        string tmp = Path.Combine(ws, "tmp.txt");
        string moved = Path.Combine(ws, "moved.txt");

        string outp;
        switch (op) {
            case "create":
                File.WriteAllText(secret, "OVERLAY-NEW");
                outp = "CREATE=" + Read(secret);
                break;
            case "renameonto":
                File.WriteAllText(tmp, "OVERLAY-ONTO");
                File.Move(tmp, secret, true);
                outp = "RENAMEONTO=" + Read(secret);
                break;
            case "renameaway":
                File.WriteAllText(secret, "OVERLAY-AWAY");
                File.Move(secret, moved, true);
                outp = "RENAMEAWAY=" + Read(moved) + " SRCAFTER=" + Read(secret);
                break;
            case "delete":
                File.WriteAllText(secret, "OVERLAY-DEL");
                File.Delete(secret);
                outp = "AFTERDEL=" + Read(secret);
                break;
            case "deletebare":
                outp = "DELETEBARE=" + Classify(() => File.Delete(secret));
                break;
            case "renamefrombare":
                outp = "RENAMEFROMBARE=" + Classify(() => File.Move(secret, moved, true));
                break;
            default:
                Console.Error.WriteLine("unknown op: " + op);
                return 2;
        }
        Console.Write(outp);
        return 0;
    }
}
