// Declared-output (-w) write-through under --write-overlay, through java.nio.
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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

public final class WriteOut {
    private static String readOrErr(Path p) {
        try {
            return Files.readString(p);
        } catch (NoSuchFileException e) {
            return "ERR:NotFound";
        } catch (IOException e) {
            return "ERR:" + e.getMessage();
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("usage: writeout_ops <declared-out> <undeclared-sibling>");
            System.exit(2);
        }
        Path out = Path.of(args[0]);
        Path sibling = Path.of(args[1]);
        Files.writeString(out, "DECLARED-OUT");
        Files.writeString(sibling, "UNDECLARED-SIB");
        System.out.write(
            ("OUT=" + readOrErr(out) + " SIB=" + readOrErr(sibling)).getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
