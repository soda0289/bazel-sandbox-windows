// Exercises the COMBINED input-filtering + write-overlay mode from a real JVM
// process: `--filter-inputs --write-overlay` with NO declared -r inputs, so the
// seeded real <execroot>\secret.txt is a HIDDEN undeclared input (masked
// NOT_FOUND). A tool output whose name collides with that hidden input must land
// in the overlay, and mutating that overlay copy must never re-reveal the real
// file.
//
// One op per invocation (the caller re-seeds a fresh secret.txt each time):
//   filter_overlay_ops <execroot> <op>
//
// Ops and the markers the test asserts on:
//   create           create over the hidden name -> CREATE=<content read back>
//   renameonto       write tmp then Files.move it ONTO the hidden name ->
//                    RENAMEONTO=<content read back>
//   renameaway       create over the hidden name then Files.move it AWAY ->
//                    RENAMEAWAY=<moved content> SRCAFTER=<orig read; ERR:NotFound>
//   delete           create over the hidden name then Files.delete it ->
//                    AFTERDEL=<orig read; ERR:NotFound>
//   deletebare       delete the hidden name with NO overlay copy ->
//                    DELETEBARE=<OK|ERR:NotFound|ERR:other>  (NOT_FOUND no-op)
//   renamefrombare   rename the hidden name away with NO overlay copy ->
//                    RENAMEFROMBARE=<OK|ERR:NotFound|ERR:other>  (NOT_FOUND no-op)
//
// Files.move/Files.delete take the path-based MoveFileEx/DeleteFile hooks. The
// read-back after delete / rename-away MUST be ERR:NotFound: once the overlay
// copy is gone the masked real input must not resurface.
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public final class FilterOverlayOps {
    private static String read(Path path) {
        try {
            return Files.readString(path);
        } catch (NoSuchFileException e) {
            return "ERR:NotFound";
        } catch (IOException e) {
            return "ERR:other";
        }
    }

    private interface FsAction {
        void run() throws IOException;
    }

    private static String classify(FsAction fn) {
        try {
            fn.run();
            return "OK";
        } catch (NoSuchFileException e) {
            return "ERR:NotFound";
        } catch (IOException e) {
            return "ERR:other";
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("usage: filter_overlay_ops <execroot> <op>");
            System.exit(2);
        }
        Path ws = Path.of(args[0]);
        String op = args[1];
        Path secret = ws.resolve("secret.txt");
        Path tmp = ws.resolve("tmp.txt");
        Path moved = ws.resolve("moved.txt");

        String out;
        switch (op) {
            case "create":
                Files.writeString(secret, "OVERLAY-NEW");
                out = "CREATE=" + read(secret);
                break;
            case "renameonto":
                Files.writeString(tmp, "OVERLAY-ONTO");
                Files.move(tmp, secret, StandardCopyOption.REPLACE_EXISTING);
                out = "RENAMEONTO=" + read(secret);
                break;
            case "renameaway":
                Files.writeString(secret, "OVERLAY-AWAY");
                Files.move(secret, moved, StandardCopyOption.REPLACE_EXISTING);
                out = "RENAMEAWAY=" + read(moved) + " SRCAFTER=" + read(secret);
                break;
            case "delete":
                Files.writeString(secret, "OVERLAY-DEL");
                Files.delete(secret);
                out = "AFTERDEL=" + read(secret);
                break;
            case "deletebare":
                out = "DELETEBARE=" + classify(() -> Files.delete(secret));
                break;
            case "renamefrombare":
                out = "RENAMEFROMBARE="
                    + classify(() -> Files.move(secret, moved, StandardCopyOption.REPLACE_EXISTING));
                break;
            default:
                System.err.println("unknown op: " + op);
                System.exit(2);
                return;
        }
        System.out.write(out.getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
