// Write-overlay VFS e2e ops, driven under the sandbox from the Go runtime.
//
// A single stdlib-only go_binary with an op dispatched on argv[1], the Go
// analogue of the python scripts/ lane. It validates the overlay against the Go
// runtime's own OS-API calls (os.Create/os.Rename/os.Remove/os.ReadDir ->
// CreateFileW/MoveFileEx/DeleteFile/FindFirstFile) and, uniquely, exercises the
// CreateProcess *working-directory* overlay redirect through os/exec - the
// rules_go GoStdlib case that motivated that fix (a compiler spawned with its
// cwd set to a per-package output dir that exists only in the overlay).
//
// Ops (each prints space-separated MARKER=value tokens the test asserts on):
//
//	fsops <ws>          write/read-back/rename/delete/move
//	enum  <ws>          enumeration splice (real + overlay-only entries)
//	filter <ws>         input-filtering: declared visible, undeclared masked
//	filteroverlay <ws> <op>  combined filter+overlay edge cases
//	spawncwd <ws>       mkdir an overlay-only dir, then os/exec a child with its
//	                    cwd set to that dir; the child writes an absolute output
//	                    path under the execroot; parent reads it back via overlay
//	spawncwdrel <ws>    like spawncwd, but the child touches files by cwd-RELATIVE
//	                    names: write+read "childrel.txt" (overlay) and read a real
//	                    input "..\seedrel.txt"; parent reads the write back
//	getcwd <ws>         spawn a child whose cwd is set to an overlay-only dir; the
//	                    child reports os.Getwd (GetCurrentDirectory), which must be
//	                    the virtual execroot path, not the backing store location
//	childcwd            child helper for spawncwd: writes an absolute output path
//	childcwdrel         child helper for spawncwdrel: cwd-relative write/read
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

// listing returns the sorted entry names of dir, joined by ",".
func listing(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "ERR:" + err.Error()
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// readOrErr reads path, mapping a not-exist error to the fixed ERR:NotFound
// marker (and any other error to ERR:other) so the test can assert masking.
func readOrErr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "ERR:NotFound"
		}
		return "ERR:other"
	}
	return string(b)
}

func classify(fn func() error) string {
	err := fn()
	if err == nil {
		return "OK"
	}
	if os.IsNotExist(err) {
		return "ERR:NotFound"
	}
	return "ERR:other"
}

func writeFile(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		die("write %s: %v", path, err)
	}
}

// fsops: write/read-back/rename/delete/move, each op visible to the next through
// the overlay in one invocation, none of it touching the real execroot.
func fsops(ws string) {
	d := filepath.Join(ws, "wd")
	if err := os.MkdirAll(d, 0o755); err != nil {
		die("mkdir wd: %v", err)
	}

	a := filepath.Join(d, "a.txt")
	writeFile(a, "OVOPS")
	read := readOrErr(a)

	b := filepath.Join(d, "b.txt")
	if err := os.Rename(a, b); err != nil {
		die("rename a->b: %v", err)
	}
	afterRename := listing(d)

	c := filepath.Join(d, "c.txt")
	writeFile(c, "TMP")
	if err := os.Remove(c); err != nil {
		die("remove c: %v", err)
	}
	afterDelete := listing(d)

	sub := filepath.Join(d, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		die("mkdir sub: %v", err)
	}
	moved := filepath.Join(sub, "b.txt")
	if err := os.Rename(b, moved); err != nil {
		die("move b->sub: %v", err)
	}
	movedContent := readOrErr(moved)

	fmt.Printf("READ=%s AFTERRENAME=%s AFTERDELETE=%s MOVED=%s",
		read, afterRename, afterDelete, movedContent)
}

// enum: a single os.ReadDir must merge the seeded REAL entries with the
// OVERLAY-ONLY entries (no duplicates), reflect the removal of an overlay entry,
// and let prefix filters resolve against the merged set - real execroot
// unchanged. Mirrors the python enum_ops lane. <ws>/mix is pre-seeded on disk.
func enum(ws string) {
	d := filepath.Join(ws, "mix")

	list1 := listing(d)

	writeFile(filepath.Join(d, "ovX.txt"), "OVX")
	writeFile(filepath.Join(d, "ovY.txt"), "OVY")
	if err := os.Mkdir(filepath.Join(d, "ovsub"), 0o755); err != nil {
		die("mkdir ovsub: %v", err)
	}
	writeFile(filepath.Join(d, "ovsub", "inner.txt"), "INNER")

	if err := os.Remove(filepath.Join(d, "ovY.txt")); err != nil {
		die("remove ovY: %v", err)
	}

	entries, err := os.ReadDir(d)
	if err != nil {
		die("readdir mix: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	list2 := strings.Join(names, ",")

	var ov, reals []string
	for _, n := range names {
		if strings.HasPrefix(n, "ov") {
			ov = append(ov, n)
		}
		if strings.HasPrefix(n, "real") {
			reals = append(reals, n)
		}
	}

	readOv := readOrErr(filepath.Join(d, "ovX.txt"))
	readReal := readOrErr(filepath.Join(d, "realA.txt"))

	fmt.Printf("LIST1=%s LIST2=%s GLOBOV=%s GLOBREAL=%s READOV=%s READREAL=%s",
		list1, list2, strings.Join(ov, ","), strings.Join(reals, ","), readOv, readReal)
}

// filter: only the declared -r input is visible; the undeclared sibling is
// masked NOT_FOUND (absent from os.ReadDir and unreadable). Mirrors filter_ops.
func filter(ws string) {
	list := listing(ws)
	readDecl := readOrErr(filepath.Join(ws, "decl.txt"))
	readSecret := readOrErr(filepath.Join(ws, "secret.txt"))
	fmt.Printf("LIST=%s READDECL=%s READSECRET=%s", list, readDecl, readSecret)
}

// filteroverlay: combined --filter-inputs --write-overlay edge cases against a
// HIDDEN undeclared input (<ws>/secret.txt, masked). Mirrors filter_overlay_ops.
func filteroverlay(ws, op string) {
	secret := filepath.Join(ws, "secret.txt")
	tmp := filepath.Join(ws, "tmp.txt")
	moved := filepath.Join(ws, "moved.txt")

	switch op {
	case "create":
		writeFile(secret, "OVERLAY-NEW")
		fmt.Printf("CREATE=%s", readOrErr(secret))
	case "renameonto":
		writeFile(tmp, "OVERLAY-ONTO")
		if err := os.Rename(tmp, secret); err != nil {
			die("rename onto: %v", err)
		}
		fmt.Printf("RENAMEONTO=%s", readOrErr(secret))
	case "renameaway":
		writeFile(secret, "OVERLAY-AWAY")
		if err := os.Rename(secret, moved); err != nil {
			die("rename away: %v", err)
		}
		fmt.Printf("RENAMEAWAY=%s SRCAFTER=%s", readOrErr(moved), readOrErr(secret))
	case "delete":
		writeFile(secret, "OVERLAY-DEL")
		if err := os.Remove(secret); err != nil {
			die("remove: %v", err)
		}
		fmt.Printf("AFTERDEL=%s", readOrErr(secret))
	case "deletebare":
		fmt.Printf("DELETEBARE=%s", classify(func() error { return os.Remove(secret) }))
	case "renamefrombare":
		fmt.Printf("RENAMEFROMBARE=%s", classify(func() error { return os.Rename(secret, moved) }))
	default:
		die("unknown filteroverlay op: %s", op)
	}
}

// spawncwd: the rules_go GoStdlib regression. Create a directory that exists
// ONLY in the write-overlay backing store, then os/exec a child process whose
// working directory is set to that overlay-only dir. Without the CreateProcess
// working-directory overlay redirect the OS cannot resolve the (absent) real
// dir and the child fails to launch with ERROR_DIRECTORY (267). With it the
// child launches from the concrete backing dir and writes its output file - the
// way rules_go's compiler does, via an ABSOLUTE path under the (virtual)
// execroot, which the overlay redirects into the backing store - and the parent
// reads it back through the overlay. (For the cwd-RELATIVE variant, where the
// child touches files by names resolved against the cwd, see spawncwdrel: the
// hook-layer reverse-map makes those resolve against the virtual execroot too.)
func spawncwd(ws string) {
	self, err := os.Executable()
	if err != nil {
		die("os.Executable: %v", err)
	}
	dir := filepath.Join(ws, "spawndir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		die("mkdir spawndir: %v", err)
	}

	out := filepath.Join(dir, "childfile.txt")
	cmd := exec.Command(self, "childcwd", out)
	cmd.Dir = dir // lpCurrentDirectory = overlay-only dir
	combined, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("SPAWN=ERR:%v OUT=%s", err, string(combined))
		os.Exit(1)
	}

	fmt.Printf("SPAWN=%s READBACK=%s", strings.TrimSpace(string(combined)), readOrErr(out))
}

// childcwd: the spawncwd child. It launched from an overlay-only cwd (proving
// the CreateProcess working-directory redirect); it writes its output to the
// absolute path argv[2] (redirected into the overlay) and prints a launch marker.
func childcwd(out string) {
	if err := os.WriteFile(out, []byte("CHILDWROTE"), 0o644); err != nil {
		fmt.Printf("CHILD=ERR:%v", err)
		os.Exit(3)
	}
	fmt.Print("CHILD=OK")
}

// spawncwdrel: like spawncwd, but the child touches files through cwd-RELATIVE
// names rather than absolute paths. From an overlay-only cwd the hook layer must
// reverse-map the (backing-resolved) relative name back to the virtual execroot so
// that (a) a relative write to an undeclared in-cone name lands in the overlay and
// reads back, and (b) a relative read of a REAL declared input one level up
// ("..\seedrel.txt", seeded on the real disk by the test) reaches it via the
// overlay's real-fallback. The parent then reads the child's overlay write back
// through the absolute virtual path.
func spawncwdrel(ws string) {
	self, err := os.Executable()
	if err != nil {
		die("os.Executable: %v", err)
	}
	dir := filepath.Join(ws, "spawnreldir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		die("mkdir spawnreldir: %v", err)
	}
	cmd := exec.Command(self, "childcwdrel")
	cmd.Dir = dir // lpCurrentDirectory = overlay-only dir -> redirected to backing
	combined, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("SPAWN=ERR:%v OUT=%s", err, string(combined))
		os.Exit(1)
	}
	fmt.Printf("SPAWN=%s READBACK=%s", strings.TrimSpace(string(combined)),
		readOrErr(filepath.Join(dir, "childrel.txt")))
}

// childcwdrel: the spawncwdrel child. Launched from an overlay-only cwd, it uses
// only cwd-RELATIVE names: write+read "childrel.txt" (undeclared -> overlay) and
// read "..\seedrel.txt" (a real declared input above the cwd).
func childcwdrel() {
	if err := os.WriteFile("childrel.txt", []byte("RELWROTE"), 0o644); err != nil {
		fmt.Printf("CHILD=WRERR:%v", err)
		os.Exit(3)
	}
	wb, err := os.ReadFile("childrel.txt")
	if err != nil {
		fmt.Printf("CHILD=RDERR:%v", err)
		os.Exit(4)
	}
	ib, err := os.ReadFile(filepath.Join("..", "seedrel.txt"))
	if err != nil {
		fmt.Printf("CHILD=INERR:%v", err)
		os.Exit(5)
	}
	fmt.Printf("CHILD=OK WROTE=%s INPUT=%s", string(wb), string(ib))
}

// getcwd: the GetCurrentDirectory reverse-map, exercised on the path that actually
// leaks the backing store - a CHILD whose working directory is set to an overlay-only
// dir. The parent's CreateProcess cwd redirect points the child at the concrete backing
// dir, so the child inherits the backing path as its OS current directory; the child
// reports os.Getwd (which on Windows always calls GetCurrentDirectory). Without the
// reverse-map hook it observes the private backing path; with it, the logical execroot
// path. (An in-process os.Chdir would NOT reproduce the leak: SetCurrentDirectory stores
// the input string verbatim, so os.Getwd would echo the virtual path regardless.)
func getcwd(ws string) {
	self, err := os.Executable()
	if err != nil {
		die("os.Executable: %v", err)
	}
	dir := filepath.Join(ws, "cwddir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		die("mkdir cwddir: %v", err)
	}
	cmd := exec.Command(self, "reportcwd")
	cmd.Dir = dir // lpCurrentDirectory = overlay-only dir -> redirected to backing
	combined, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("WD=ERR:%v OUT=%s", err, string(combined))
		os.Exit(1)
	}
	fmt.Printf("WD=%s", strings.TrimSpace(string(combined)))
}

// reportcwd: the getcwd child. Launched from an overlay-only cwd, it prints os.Getwd,
// which must be the virtual execroot path once the reverse-map hook maps the inherited
// backing cwd back.
func reportcwd() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("ERR:%v", err)
		os.Exit(3)
	}
	fmt.Print(wd)
}

// writeout: write to a DECLARED OUTPUT path and to an UNDECLARED sibling, then
// read both back. The test declares the first as -w (so it must write THROUGH to
// the real execroot) and leaves the second undeclared (so it must be redirected
// into the overlay); it asserts real-disk placement afterwards. Both reads
// succeed in-process (overlay read-after-write covers the redirected sibling).
func writeout(out, sibling string) {
	writeFile(out, "DECLARED-OUT")
	writeFile(sibling, "UNDECLARED-SIB")
	fmt.Printf("OUT=%s SIB=%s", readOrErr(out), readOrErr(sibling))
}

func main() {
	if len(os.Args) < 2 {
		die("usage: ops <fsops|enum|filter|filteroverlay|spawncwd|childcwd|writeout> [args...]")
	}
	op := os.Args[1]
	if op == "childcwd" {
		if len(os.Args) < 3 {
			die("usage: ops childcwd <abs-output-path>")
		}
		childcwd(os.Args[2])
		return
	}
	if op == "reportcwd" {
		reportcwd()
		return
	}
	if op == "childcwdrel" {
		childcwdrel()
		return
	}
	if op == "writeout" {
		if len(os.Args) < 4 {
			die("usage: ops writeout <declared-out> <undeclared-sibling>")
		}
		writeout(os.Args[2], os.Args[3])
		return
	}

	if len(os.Args) < 3 {
		die("usage: ops %s <execroot> [op]", op)
	}
	ws := os.Args[2]
	switch op {
	case "fsops":
		fsops(ws)
	case "enum":
		enum(ws)
	case "filter":
		filter(ws)
	case "filteroverlay":
		if len(os.Args) < 4 {
			die("usage: ops filteroverlay <execroot> <op>")
		}
		filteroverlay(ws, os.Args[3])
	case "getcwd":
		getcwd(ws)
	case "spawncwd":
		spawncwd(ws)
	case "spawncwdrel":
		spawncwdrel(ws)
	default:
		die("unknown op: %s", op)
	}
}
