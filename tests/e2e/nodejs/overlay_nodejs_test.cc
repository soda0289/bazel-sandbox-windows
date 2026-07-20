// Write-overlay VFS end-to-end tests against hermetic Node.js.
//
// The JavaScript each test runs lives in real .js files under scripts/ (carried
// as cc_test data, resolved from runfiles via env vars) rather than inline in
// this TU, so the scripts are lintable, editable, and reusable.
//
//   NodeFsReadBackAndListing        scripts/fs_readback.js  - write -> readdir
//                                   -> copy -> read back in one invocation.
//   NodeFsMutationOps               scripts/fs_ops.js       - write/read/rename/
//                                   move/delete, each op visible to the next.
//   NodeModulesTreeCopiedIntoOverlay scripts/node_modules_stress.js - copy a
//                                   real React + Angular node_modules tree
//                                   (~18k files) through the overlay.
//
// Every test asserts the three overlay invariants: read-after-write, an
// enumeration splice, and an unchanged real execroot (skips if its tool/data
// env var is missing).

#include <windows.h>

#include <filesystem>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/e2e/e2e_harness.h"

namespace bsxe2e {
namespace {

namespace fs = std::filesystem;

bool Contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

std::wstring NodeExe() { return OverlayTest::ToolFromEnv("E2E_NODE"); }

// Resolves a .js script carried as cc_test data from its runfiles env var.
std::wstring Script(const char* envName) { return OverlayTest::ToolFromEnv(envName); }

TEST_F(OverlayTest, NodeFsReadBackAndListing) {
    std::wstring node = NodeExe();
    if (node.empty()) GTEST_SKIP() << "node.exe missing from runfiles (E2E_NODE)";
    std::wstring script = Script("E2E_JS_FSREADBACK");
    if (script.empty()) GTEST_SKIP() << "fs_readback.js missing (E2E_JS_FSREADBACK)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {node, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "in.txt")) << "readdir did not splice overlay file:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READ=OVNODE")) << "copyFile read-back failed:\n" << r.out;

    // The whole wd/ tree lived only in the overlay: the real execroot is empty.
    EXPECT_TRUE(Snapshot(ws).empty()) << "node writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

TEST_F(OverlayTest, NodeFsMutationOps) {
    std::wstring node = NodeExe();
    if (node.empty()) GTEST_SKIP() << "node.exe missing from runfiles (E2E_NODE)";
    std::wstring script = Script("E2E_JS_FSOPS");
    if (script.empty()) GTEST_SKIP() << "fs_ops.js missing (E2E_JS_FSOPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {node, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // write -> read-back through the overlay.
    EXPECT_TRUE(Contains(r.out, "READ=OVOPS")) << "read-after-write failed:\n" << r.out;
    // rename a.txt -> b.txt: listing shows b.txt and no longer a.txt.
    EXPECT_TRUE(Contains(r.out, "AFTERRENAME=b.txt")) << "rename not reflected in listing:\n" << r.out;
    // create + delete c.txt: listing no longer contains c.txt.
    EXPECT_FALSE(Contains(r.out, "AFTERDELETE=b.txt,c.txt")) << "delete not reflected in listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "AFTERDELETE=b.txt")) << "delete removed too much:\n" << r.out;
    // move b.txt into sub/ then read it back at its new path.
    EXPECT_TRUE(Contains(r.out, "MOVED=OVOPS")) << "move + read-back failed:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "node writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

// Enumeration is the overlay's hardest area: a single directory listing must
// splice overlay-only entries into a directory that already has real on-disk
// entries (without duplicates), reflect the removal of an overlay-created
// entry, and let prefix filters resolve against the merged set - all without
// disturbing the immutable real execroot. (Deleting/renaming a REAL visible
// file is denied by design - see docs/design/detours-write-overlay-vfs.md
// §6.3.1 - so this exercises the merge, not a mutation of real entries.)
TEST_F(OverlayTest, NodeEnumerationSplice) {
    std::wstring node = NodeExe();
    if (node.empty()) GTEST_SKIP() << "node.exe missing from runfiles (E2E_NODE)";
    std::wstring script = Script("E2E_JS_ENUMOPS");
    if (script.empty()) GTEST_SKIP() << "enum_ops.js missing (E2E_JS_ENUMOPS)";

    auto ws = NewWorkspace();
    // Seed a directory with two REAL on-disk files (allowed in-cone reads). The
    // sandboxed script splices overlay-only entries alongside these.
    auto mix = Join(ws, L"mix");
    ASSERT_TRUE(CreateDirectoryW(mix.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(mix, L"realA.txt"), "REALA");
    WriteText(Join(mix, L"realB.txt"), "REALB");

    auto r = RunOverlay(ws, {node, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Baseline: both seeded real entries enumerate through the passthrough.
    EXPECT_TRUE(Contains(r.out, "LIST1=realA.txt,realB.txt")) << "real passthrough enumeration failed:\n" << r.out;
    // Merged view: overlay-only file + subdir spliced in alongside the reals,
    // with the deleted overlay entry (ovY.txt) gone. Sort is by UTF-16 code
    // unit: uppercase 'X' < lowercase 's', so ovX.txt < ovsub, then real*.
    EXPECT_TRUE(Contains(r.out, "LIST2=ovX.txt,ovsub,realA.txt,realB.txt")) << "enumeration splice failed:\n" << r.out;
    // Prefix filters resolve against the merged set: "ov" only the overlay
    // entries, "real" only the real ones.
    EXPECT_TRUE(Contains(r.out, "GLOBOV=ovX.txt,ovsub")) << "filter missed overlay entries:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "GLOBREAL=realA.txt,realB.txt")) << "filter missed real entries:\n" << r.out;
    // Read-back through both halves of the merge.
    EXPECT_TRUE(Contains(r.out, "READOV=OVX")) << "overlay read-back failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READREAL=REALA")) << "real passthrough read failed:\n" << r.out;

    // The real execroot is untouched: only the seeded mix/ dir + its two real
    // files remain; no overlay entry leaked to disk.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(3u, snap.size()) << "overlay entries leaked onto the real execroot";
    EXPECT_TRUE(Exists(Join(mix, L"realA.txt"))) << "seeded real file vanished";
    EXPECT_TRUE(Exists(Join(mix, L"realB.txt"))) << "seeded real file vanished";
    EXPECT_FALSE(Exists(Join(mix, L"ovX.txt"))) << "overlay create leaked to the real disk";
    EXPECT_FALSE(Exists(Join(mix, L"ovsub"))) << "overlay subdir leaked to the real disk";
}

TEST_F(OverlayTest, NodeModulesTreeCopiedIntoOverlay) {
    std::wstring node = NodeExe();
    if (node.empty()) GTEST_SKIP() << "node.exe missing from runfiles (E2E_NODE)";
    std::wstring script = Script("E2E_JS_NODEMODULES");
    if (script.empty()) GTEST_SKIP() << "node_modules_stress.js missing (E2E_JS_NODEMODULES)";
    std::wstring nmRoot = OverlayTest::ToolFromEnv("E2E_NODE_MODULES");
    if (nmRoot.empty()) GTEST_SKIP() << "node_modules tree missing (E2E_NODE_MODULES)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {node, script, nmRoot, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Enumeration splice: the overlay-only packages appear in the listing.
    EXPECT_TRUE(Contains(r.out, "@angular")) << "node_modules listing missing @angular:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "react")) << "node_modules listing missing react:\n" << r.out;
    // Read-after-write on a deep file: @angular/core/package.json reads back.
    EXPECT_TRUE(Contains(r.out, "ANGVER=18.2.13")) << "deep overlay read-back failed:\n" << r.out;

    // Thousands of files were "written" - all into the backing store. The real
    // execroot is untouched: no node_modules on disk at all.
    EXPECT_TRUE(Snapshot(ws).empty()) << "node_modules writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"node_modules"))) << "overlay node_modules leaked onto real disk";
}

// msys2 bash is required to run a rules_js js_binary launcher on Windows (the
// native .bat launcher shells out to bash to run the .sh launcher - exactly
// what `bazel run` does). Non-hermetic: skip if it is not installed.
constexpr wchar_t kMsysBash[] = L"C:\\msys64\\usr\\bin\\bash.exe";

// Runs a rules_js js_binary launcher UNDER the sandbox and asserts the build's
// output is virtualized into the overlay rather than written to the real disk.
//
// This is the "formal build" analogue of the fs tests: instead of a hand-
// written script, a real bundler (driven by the same launcher `bazel run`
// invokes) does thousands of reads/writes through the overlay. The launcher's
// runfiles root is the write cone (-W); the bundler runs there and writes its
// output tree into the cone, so every output write is redirected into the
// process-private backing store and the real runfiles tree stays unchanged.
//
// `launcherEnv`  - env var holding the js_binary launcher rlocationpath.
// `pkgRelDir`    - the app package path under the runfiles _main root (the
//                  launcher chdir's here; its output dir lands under it).
// `okMarkers`    - substrings that must appear in the captured output.
// `outSubdir`    - the build output dir (relative to the app dir) that must NOT
//                  appear on the real disk.
// `readBackRel`  - optional path (relative to the app dir) of a build output
//                  file to read back THROUGH the overlay in the SAME sandbox
//                  invocation. When set, the launcher and a `type` of this file
//                  are chained with "&&" inside one .bat, and `okMarkers` are
//                  matched against the typed content - positive proof the build
//                  emitted into the overlay (needed for tools that are silent on
//                  success, e.g. ngc). When empty, `okMarkers` match the tool's
//                  own stdout (e.g. vite prints its output summary).
void RunJsBinaryBuildUnderOverlay(OverlayTest& t, const char* launcherEnv,
                                   const std::wstring& pkgRelDir,
                                   const std::vector<const char*>& okMarkers,
                                   const std::wstring& outSubdir,
                                   const std::wstring& readBackRel = L"") {
    std::wstring launcher = OverlayTest::ToolFromEnv(launcherEnv);
    if (launcher.empty()) GTEST_SKIP() << "js_binary launcher missing (" << launcherEnv << ")";
    if (!OverlayTest::Exists(kMsysBash))
        GTEST_SKIP() << "msys2 bash.exe not found; required to run the rules_js js_binary launcher";

    // launcher = <runfiles>/_main/<pkg>/<name>_/<name>.bat. Strip the launcher
    // file and its "<name>_" dir (2 levels), then one level per <pkg> component
    // to reach the runfiles _main root.
    fs::path lp(launcher);
    fs::path mainroot = lp.parent_path().parent_path();
    for (auto part : fs::path(pkgRelDir)) {
        (void)part;
        mainroot = mainroot.parent_path();
    }
    fs::path appdir = mainroot / pkgRelDir;
    std::wstring cone = mainroot.make_preferred().wstring();

    // The sandbox sets the child cwd to the -W cone (= runfiles _main, whose
    // path contains "bazel-out"), so the launcher self-locates without needing
    // BAZEL_BINDIR, chdir's into the app package, and builds there.
    RunResult r;
    if (readBackRel.empty()) {
        r = t.RunOverlay(cone, {OverlayTest::CmdExe(), L"/c", launcher, L"build"});
    } else {
        // Run the build, then (only if it succeeds) read an emitted file back
        // through the overlay: `type` sees the virtualized output, proving the
        // write landed in the backing store. If the build fails, `type` is
        // skipped and the markers are absent -> the assertion fails.
        fs::path readBack = (appdir / readBackRel).make_preferred();
        std::wstring line = L"\"" + launcher + L"\" build && type \"" + readBack.wstring() + L"\"";
        r = t.RunOverlayBat(cone, {line});
    }

    EXPECT_EQ(0, r.code) << r.out;
    for (const char* m : okMarkers) {
        EXPECT_TRUE(Contains(r.out, m)) << "missing build marker '" << m << "':\n" << r.out;
    }
    // The build output tree was written entirely into the overlay backing
    // store: it must not exist on the real runfiles tree.
    EXPECT_FALSE(OverlayTest::Exists((appdir / outSubdir).make_preferred().wstring()))
        << "build output leaked onto the real disk at " << (appdir / outSubdir).string();
}

TEST_F(OverlayTest, ViteReactBuildVirtualizedIntoOverlay) {
    // vite colorizes output (ANSI codes split the "dist/" prefix from the
    // basename), so assert on contiguous basenames + the completion marker.
    RunJsBinaryBuildUnderOverlay(
        *this, "E2E_VITE_REACT", L"apps/react_app",
        {"built in", "index.js", "index.html"}, L"dist");
}

TEST_F(OverlayTest, NgcAngularBuildVirtualizedIntoOverlay) {
    // ngc (the Angular compiler) is silent on success, so we prove emission by
    // reading a compiled file back THROUGH the overlay in the same invocation.
    // The Angular compiler is the only thing that produces "defineComponent",
    // so its presence in the (virtualized) out/app.component.js is unambiguous
    // proof the compile ran and its output landed in the backing store.
    RunJsBinaryBuildUnderOverlay(
        *this, "E2E_NGC_ANGULAR", L"apps/ng_app",
        {"AppComponent", "defineComponent"}, L"out",
        L"out/app.component.js");
}

}  // namespace
}  // namespace bsxe2e
