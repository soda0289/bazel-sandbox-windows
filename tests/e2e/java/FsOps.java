// Exercises the full set of Java file-system mutation ops through the
// write-overlay in a single --write-overlay invocation: write, read-back,
// rename, move (into a subdir), delete. Each mutation must be visible to
// subsequent ops within the same invocation (overlay read-after-write +
// enumeration splice), and none of it may touch the real execroot.
//
// This is the Java analogue of tests/e2e/dotnet/fs_ops.cs: it drives the same
// read/write/move/rename/delete sequence, but through java.nio.file (whose
// Windows implementation calls CreateFileW / MoveFileEx / DeleteFile /
// FindFirstFile under the hood), so the overlay is validated against the JVM's
// OS-API patterns.
//
// Run as: fs_ops <execroot>
// Emits a space-separated set of markers the test asserts on:
//   READ=<content>            content read back after write
//   AFTERRENAME=<entries>     dir listing after renaming a.txt -> b.txt
//   AFTERDELETE=<entries>     dir listing after creating+deleting c.txt
//   MOVED=<content>           content read back after moving b.txt into sub/
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

public final class FsOps {
    private static String listDir(Path dir) throws IOException {
        List<String> names = new ArrayList<>();
        try (Stream<Path> s = Files.list(dir)) {
            s.forEach(p -> names.add(p.getFileName().toString()));
        }
        Collections.sort(names);  // lexicographic by UTF-16 code unit (ordinal)
        return String.join(",", names);
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: fs_ops <execroot>");
            System.exit(2);
        }
        Path ws = Path.of(args[0]);
        Path d = ws.resolve("wd");
        Files.createDirectories(d);

        // write + read-back
        Path a = d.resolve("a.txt");
        Files.writeString(a, "OVJAVA");
        String read = Files.readString(a);

        // rename a.txt -> b.txt (same dir); the listing must show b.txt, not a.txt
        Path b = d.resolve("b.txt");
        Files.move(a, b);
        String afterRename = listDir(d);

        // create then delete c.txt; the listing must no longer contain c.txt
        Path c = d.resolve("c.txt");
        Files.writeString(c, "TMP");
        Files.delete(c);
        String afterDelete = listDir(d);

        // move b.txt into a freshly created subdirectory, then read it back there
        Path sub = d.resolve("sub");
        Files.createDirectories(sub);
        Path moved = sub.resolve("b.txt");
        Files.move(b, moved, StandardCopyOption.REPLACE_EXISTING);
        String movedContent = Files.readString(moved);

        System.out.write((
            "READ=" + read
            + " AFTERRENAME=" + afterRename
            + " AFTERDELETE=" + afterDelete
            + " MOVED=" + movedContent).getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
