// The rules_go GoStdlib regression, through Java's ProcessBuilder (the Python/
// Node/.NET analogue of GoSpawnOverlayOnlyCwd). Creates a directory that exists
// ONLY in the overlay backing store, then launches a child (this same
// java_binary launcher, re-entered via `childcwd`) with that overlay-only dir
// as its working directory (ProcessBuilder.directory() -> CreateProcessW
// lpCurrentDirectory, WITHOUT any preceding SetCurrentDirectory). Without the
// CreateProcess working-directory overlay redirect the child fails to launch
// (ERROR_DIRECTORY 267); with it the child launches from the concrete backing
// dir and writes its output (an absolute path under the virtual execroot) into
// the overlay, which the parent reads back. The real execroot stays untouched.
//
// Run as: spawn_ops spawncwd <execroot> <self-launcher-path>   # parent
//         spawn_ops childcwd <out-path>                        # child re-entry
// Parent emits:  SPAWN=<child-stdout> READBACK=<content-read-through-overlay>
// Child emits:   CHILD=OK
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class SpawnOps {
    private static void childcwd(String out) throws IOException {
        Files.writeString(Path.of(out), "CHILDWROTE");
        System.out.write("CHILD=OK".getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length < 2) {
            System.err.println("usage: spawn_ops spawncwd <execroot> <self> | childcwd <out>");
            System.exit(2);
        }
        if (args[0].equals("childcwd")) {
            childcwd(args[1]);
            return;
        }
        // parent: spawncwd <execroot> <self-launcher-path>
        Path d = Path.of(args[1], "spawndir");
        Files.createDirectories(d);
        Path out = d.resolve("childfile.txt");

        ProcessBuilder pb = new ProcessBuilder(args[2], "childcwd", out.toString());
        pb.directory(d.toFile());  // lpCurrentDirectory = overlay-only dir
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String childOut = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        if (code != 0) {
            System.out.write(("SPAWN=ERR:" + code + " OUT=" + childOut).getBytes(StandardCharsets.UTF_8));
            System.out.flush();
            System.exit(1);
        }
        String readback = Files.readString(out);
        System.out.write(
            ("SPAWN=" + childOut.trim() + " READBACK=" + readback).getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
