// Exercises the sandbox's *input-filtering* mode (the mode Bazel uses in
// production) from a real JVM process. Only the declared -r inputs are visible;
// every other real file under the execroot is masked NOT_FOUND and hidden from
// enumeration.
//
// This drives Java's own OS-API paths for both halves of the guarantee:
//   - Files.list (-> FindFirstFile/FindNextFile) must NOT surface the
//     undeclared sibling, and
//   - Files.readString of the undeclared sibling must throw NoSuchFileException
//     (the mask presents it as absent, not access-denied).
//
// The test seeds <execroot>/decl.txt (declared -r) and <execroot>/secret.txt
// (undeclared) before invoking the sandbox with `--filter-inputs ... -r decl.txt`.
//
// Run as: filter_ops <execroot>
// Emits space-separated markers the test asserts on:
//   LIST=<entries>        listing of the execroot (declared visible, undeclared hidden)
//   READDECL=<content>    read-back of the declared input
//   READSECRET=<content|ERR:NotFound|ERR:other>  attempted read of the undeclared file
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

public final class FilterOps {
    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: filter_ops <execroot>");
            System.exit(2);
        }
        Path ws = Path.of(args[0]);

        List<String> names = new ArrayList<>();
        try (Stream<Path> s = Files.list(ws)) {
            s.forEach(p -> names.add(p.getFileName().toString()));
        }
        Collections.sort(names);
        String listing = String.join(",", names);

        String readDecl = Files.readString(ws.resolve("decl.txt"));

        String readSecret;
        try {
            readSecret = Files.readString(ws.resolve("secret.txt"));
        } catch (NoSuchFileException e) {
            readSecret = "ERR:NotFound";
        } catch (IOException e) {
            readSecret = "ERR:other";
        }

        System.out.write((
            "LIST=" + listing
            + " READDECL=" + readDecl
            + " READSECRET=" + readSecret).getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
