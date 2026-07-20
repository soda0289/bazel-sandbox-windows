// Stresses the write-overlay's *enumeration splice* through Java's directory
// APIs (Files.newDirectoryStream -> FindFirstFile/FindNextFile). Enumeration is
// the overlay's hardest area: a single listing of one directory must merge the
// REAL on-disk entries (returned by the underlying FindFirstFile) with the
// OVERLAY-ONLY entries (created this process into the backing store) - without
// duplicates, honoring glob filters, and reflecting the removal of an
// overlay-created entry - all while the real execroot stays byte-for-byte
// unchanged.
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
// Run as: enum_ops <execroot>
// Emits a space-separated set of markers the test asserts on:
//   LIST1=<entries>     baseline listing of the seeded (real) dir
//   LIST2=<entries>     listing after splicing overlay entries + one deletion
//   GLOBOV=<entries>    newDirectoryStream(dir, "ov*") over the merge
//   GLOBREAL=<entries>  ... "real*" over the merge
//   READOV=<content>    read-back of an overlay-only file
//   READREAL=<content>  passthrough read-back of a real file
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

public final class EnumOps {
    private static String list(Path dir) throws IOException {
        List<String> names = new ArrayList<>();
        try (Stream<Path> s = Files.list(dir)) {
            s.forEach(p -> names.add(p.getFileName().toString()));
        }
        Collections.sort(names);
        return String.join(",", names);
    }

    private static String glob(Path dir, String pattern) throws IOException {
        List<String> names = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, pattern)) {
            for (Path p : ds) {
                names.add(p.getFileName().toString());
            }
        }
        Collections.sort(names);
        return String.join(",", names);
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: enum_ops <execroot>");
            System.exit(2);
        }
        Path ws = Path.of(args[0]);
        Path d = ws.resolve("mix");  // pre-seeded on the real disk

        // baseline: the seeded real entries enumerate through the passthrough
        String list1 = list(d);

        // splice overlay-only entries (files + a subdir) into the SAME directory
        // that already holds the real entries
        Files.writeString(d.resolve("ovX.txt"), "OVX");
        Files.writeString(d.resolve("ovY.txt"), "OVY");
        Files.createDirectories(d.resolve("ovsub"));
        Files.writeString(d.resolve("ovsub").resolve("inner.txt"), "INNER");

        // delete one OVERLAY-created entry: it must drop out of the merged view
        // while the real entries (and the other overlay entries) remain
        Files.delete(d.resolve("ovY.txt"));

        // merged view: realA/realB + ovX.txt + ovsub, but not ovY.txt
        String list2 = list(d);

        // glob enumeration over the merged set, both halves
        String globOv = glob(d, "ov*");
        String globReal = glob(d, "real*");

        // read-back: an overlay-only file and a real (passthrough) file
        String readOv = Files.readString(d.resolve("ovX.txt"));
        String readReal = Files.readString(d.resolve("realA.txt"));

        System.out.write((
            "LIST1=" + list1
            + " LIST2=" + list2
            + " GLOBOV=" + globOv
            + " GLOBREAL=" + globReal
            + " READOV=" + readOv
            + " READREAL=" + readReal).getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
