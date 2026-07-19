// Read-enforcement MODE: permissive (default) vs hermetic (-H), plus
// --filter-inputs (undeclared inputs masked NOT_FOUND and hidden from
// enumeration), output-parent-dir revelation, --execroot-writable, and
// cleanup-on-exit of undeclared scratch.
//
// gtest port of tests/enforce/modes.ps1. Uses RunProbeRaw (no implicit -H) so
// each case controls the read mode explicitly.

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

// --- Reads inside the working dir -------------------------------------------

TEST_F(EnforceTest, PermissiveUndeclaredReadInsideWorkdirAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws}, {L"read", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, HermeticUndeclaredReadInsideWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbeRaw({L"-H", L"-W", ws}, {L"read", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, HermeticReadInsideWorkdirWithScopeAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-H", L"-W", ws, L"-r", ws}, {L"read", Join(ws, L"a.txt")}));
}

// --- Absent-file probing tracks the mode ------------------------------------

TEST_F(EnforceTest, PermissiveAbsentReadInsideWorkdirReportsNotFound) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kNotFound, RunProbeRaw({L"-W", ws}, {L"read", Join(ws, L"nope.txt")}));
}

TEST_F(EnforceTest, HermeticAbsentReadInsideWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbeRaw({L"-H", L"-W", ws}, {L"read", Join(ws, L"nope.txt")}));
}

// --- Writes are confined in BOTH modes --------------------------------------

TEST_F(EnforceTest, PermissiveUndeclaredWriteInsideWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws}, {L"write", Join(ws, L"w1.txt")}));
}

TEST_F(EnforceTest, PermissiveWriteInsideWorkdirWithScopeAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"-w", ws}, {L"write", Join(ws, L"w2.txt")}));
}

TEST_F(EnforceTest, HermeticUndeclaredWriteInsideWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbeRaw({L"-H", L"-W", ws}, {L"write", Join(ws, L"w3.txt")}));
}

// --- -b blocks reads even in permissive mode --------------------------------
TEST_F(EnforceTest, PermissiveBlockStillBlocksReads) {
    auto ws = NewWorkspace();
    auto blocked = Join(ws, L"sub");
    WriteText(Join(blocked, L"sfile.txt"), "secret");
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws, L"-b", blocked},
                                   {L"read", Join(blocked, L"sfile.txt")}));
}

// --- Reads OUTSIDE -W are allowed in both modes -----------------------------
TEST_F(EnforceTest, HermeticReadOutsideWorkdirAllowed) {
    auto ws = NewWorkspace();
    auto outside = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-H", L"-W", ws}, {L"read", Join(outside, L"a.txt")}));
}

// --- --filter-inputs: undeclared inputs are INVISIBLE (masked NOT_FOUND) -----
TEST_F(EnforceTest, FilterInputsDeclaredReadAllowed) {
    auto fi = NewWorkspace();
    auto vis = Join(fi, L"a.txt");
    EXPECT_EQ(kOk, RunProbeRaw({L"--filter-inputs", L"-W", fi, L"-r", vis}, {L"read", vis}));
}

TEST_F(EnforceTest, FilterInputsUndeclaredReadMasked) {
    auto fi = NewWorkspace();
    auto vis = Join(fi, L"a.txt");
    auto hidden = Join(fi, L"secret.txt");
    WriteText(hidden, "top secret");
    EXPECT_EQ(kNotFound, RunProbeRaw({L"--filter-inputs", L"-W", fi, L"-r", vis}, {L"read", hidden}));
}

TEST_F(EnforceTest, FilterInputsUndeclaredNtReadMasked) {
    auto fi = NewWorkspace();
    auto vis = Join(fi, L"a.txt");
    auto hidden = Join(fi, L"secret.txt");
    WriteText(hidden, "top secret");
    EXPECT_EQ(kNotFound, RunProbeRaw({L"--filter-inputs", L"-W", fi, L"-r", vis}, {L"ntread", hidden}));
}

// Consistency matrix: EVERY read/probe hook variant must mask IDENTICALLY. Each
// op exercises a different detoured hook that resolves a single path.
TEST_F(EnforceTest, FilterInputsReadProbeConsistencyMatrix) {
    auto fi = NewWorkspace();
    auto vis = Join(fi, L"a.txt");
    auto hidden = Join(fi, L"secret.txt");
    WriteText(hidden, "top secret");
    auto absent = Join(fi, L"absent.txt");
    auto absentNested = Join(fi, L"no\\such\\deep\\path");
    struct State {
        const wchar_t* name;
        std::wstring path;
        int want;
    };
    std::vector<State> states = {
        {L"undeclared-existing", hidden, kNotFound},
        {L"absent", absent, kNotFound},
        {L"absent-nested", absentNested, kNotFound},
        {L"declared-r-visible", vis, kOk},
    };
    const wchar_t* ops[] = {L"read",  L"ntread", L"reada",     L"stat",
                            L"stata", L"statex", L"statbyname", L"findfile"};
    for (const wchar_t* op : ops) {
        for (const auto& st : states) {
            SCOPED_TRACE(std::string("op=") + std::string(op, op + wcslen(op)));
            SCOPED_TRACE(std::string("state=") + std::string(st.name, st.name + wcslen(st.name)));
            EXPECT_EQ(st.want, RunProbeRaw({L"--filter-inputs", L"-W", fi, L"-r", vis},
                                           {op, st.path}));
        }
    }
}

// Compound ops that perform a SOURCE READ must mask their source-read denial too.
TEST_F(EnforceTest, FilterInputsCompoundSourceReadMasked) {
    auto fi = NewWorkspace();
    auto vis = Join(fi, L"a.txt");
    auto hidden = Join(fi, L"secret.txt");
    WriteText(hidden, "top secret");
    auto cpdst = Join(fi, L"copydst");
    MakeDirs(cpdst);
    EXPECT_EQ(kNotFound, RunProbeRaw({L"--filter-inputs", L"-W", fi, L"-r", vis, L"-w", cpdst},
                                     {L"copy", hidden, Join(cpdst, L"o.txt")}));
    EXPECT_EQ(kNotFound, RunProbeRaw({L"--filter-inputs", L"-W", fi, L"-r", vis, L"-w", cpdst},
                                     {L"hardlink", Join(cpdst, L"lnk.txt"), hidden}));
    // Writes are NOT masked.
    EXPECT_EQ(kDenied, RunProbeRaw({L"--filter-inputs", L"-W", fi, L"-r", vis},
                                   {L"write", Join(fi, L"wx.txt")}));
    // Plain -H (no --filter-inputs) keeps ACCESS_DENIED for undeclared reads.
    EXPECT_EQ(kDenied, RunProbeRaw({L"-H", L"-W", fi}, {L"read", hidden}));
}

// Colocated UNDECLARED package.json is masked (hermetic/RBE parity).
TEST_F(EnforceTest, FilterInputsColocatedPackageJsonMasked) {
    auto fi = NewWorkspace();
    auto vis = Join(fi, L"a.txt");
    auto pkg = Join(fi, L"package.json");
    WriteText(pkg, "{\"type\":\"commonjs\"}");
    std::vector<std::wstring> grants = {L"--filter-inputs", L"-W", fi, L"-r", vis};
    EXPECT_EQ(kNotFound, RunProbeRaw(grants, {L"read", pkg}));
    EXPECT_EQ(kNotFound, RunProbeRaw(grants, {L"stat", pkg}));
    EXPECT_EQ(kNotFound, RunProbeRaw(grants, {L"statbyname", pkg}));
    EXPECT_EQ(kNotFound, RunProbeRaw(grants, {L"statex", pkg}));
    EXPECT_EQ(kNotFound, RunProbeRaw(grants, {L"enumfind", fi, L"package.json"}));
}

// Undeclared entries are hidden from directory ENUMERATION across all three
// enumeration code paths, for both plain and \\?\ directory forms.
TEST_F(EnforceTest, FilterInputsEnumerationHidesUndeclared) {
    auto en = NewWorkspace();
    MakeDirs(Join(en, L"sub"));    // ancestor of a declared input (seeded by NewWorkspace)
    MakeDirs(Join(en, L"other"));  // undeclared directory
    auto enVis = Join(en, L"a.txt");
    auto enDeep = Join(en, L"sub\\deep.txt");
    WriteText(enDeep, "deep");
    WriteText(Join(en, L"secret.txt"), "top secret");
    std::vector<std::wstring> grants = {L"--filter-inputs", L"-W", en, L"-r", enVis, L"-r", enDeep};
    const wchar_t* ops[] = {L"enumfind", L"enumfindnt", L"enumfindntdirect"};
    for (const std::wstring dir : {en, L"\\\\?\\" + en}) {
        for (const wchar_t* op : ops) {
            SCOPED_TRACE(std::string(op, op + wcslen(op)));
            EXPECT_EQ(kOk, RunProbeRaw(grants, {op, dir, L"a.txt"}));
            EXPECT_EQ(kNotFound, RunProbeRaw(grants, {op, dir, L"secret.txt"}));
            EXPECT_EQ(kOk, RunProbeRaw(grants, {op, dir, L"sub"}));
            EXPECT_EQ(kNotFound, RunProbeRaw(grants, {op, dir, L"other"}));
        }
    }
}

// --- output parent directories (derived from -w, no CLI flag) ----------------
TEST_F(EnforceTest, OutputParentDirRevelation) {
    auto od = NewWorkspace();
    auto outdir = Join(od, L"bin");
    auto outfile = Join(outdir, L"gen.txt");
    auto deepfile = Join(od, L"a\\b\\c\\deep.txt");
    auto secret = Join(outdir, L"secret.txt");
    MakeDirs(outdir);
    WriteText(secret, "top secret");

    // Baseline: no -w touching the dir -> hidden, create denied (hard ACCESS_DENIED).
    EXPECT_EQ(kDenied, RunProbeRaw({L"--filter-inputs", L"-W", od}, {L"mkdir", outdir}));
    // -w on the declared output reveals + pre-creates the parent dir chain, so a
    // tool's mkdir reaches ALREADY_EXISTS (20) instead of ACCESS_DENIED.
    EXPECT_EQ(kOtherError, RunProbeRaw({L"--filter-inputs", L"-W", od, L"-w", outfile}, {L"mkdir", outdir}));
    EXPECT_EQ(kOtherError, RunProbeRaw({L"--filter-inputs", L"-W", od, L"-w", deepfile},
                                       {L"mkdir", Join(od, L"a\\b\\c")}));
    // The declared output write into the revealed dir succeeds.
    EXPECT_EQ(kOk, RunProbeRaw({L"--filter-inputs", L"-W", od, L"-w", outfile}, {L"write", outfile}));
    // Revealing the dir exposes the DIRECTORY only, not its contents.
    EXPECT_EQ(kNotFound, RunProbeRaw({L"--filter-inputs", L"-W", od, L"-w", outfile}, {L"read", secret}));
    EXPECT_EQ(kDenied, RunProbeRaw({L"--filter-inputs", L"-W", od, L"-w", outfile}, {L"write", secret}));
    EXPECT_EQ(kNotFound, RunProbeRaw({L"--filter-inputs", L"-W", od, L"-w", outfile},
                                     {L"enumfind", outdir, L"secret.txt"}));
}

// --- --execroot-writable: create-new allowed, clobber-existing denied ----------
TEST_F(EnforceTest, ExecrootWritable) {
    auto ew = NewWorkspace();
    auto ewNew = Join(ew, L"scratch.tmp");
    auto ewNewDir = Join(ew, L"scratchdir");
    auto ewExisting = Join(ew, L"a.txt");   // seeded (undeclared)
    auto ewOut = Join(ew, L"out.txt");
    WriteText(ewOut, "declared output");
    auto ewInput = Join(ew, L"src.txt");    // seeded; declared -r

    std::vector<std::wstring> base = {L"--filter-inputs", L"--execroot-writable", L"-W", ew};
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"write", ewNew}));
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"mkdir", ewNewDir}));
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"rewrite", Join(ew, L"rescratch.tmp")}));
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"writeread", Join(ew, L"wrscratch.tmp")}));
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"writedelete", Join(ew, L"wdscratch.tmp")}));
    // Overwriting a pre-existing undeclared file is DENIED.
    EXPECT_EQ(kDenied, RunProbeRaw(base, {L"write", ewExisting}));
    // Overwriting a pre-existing declared -r input is DENIED.
    EXPECT_EQ(kDenied, RunProbeRaw({L"--filter-inputs", L"--execroot-writable", L"-W", ew, L"-r", ewInput},
                                   {L"write", ewInput}));
    // A declared -w output stays freely overwritable.
    EXPECT_EQ(kOk, RunProbeRaw({L"--filter-inputs", L"--execroot-writable", L"-W", ew, L"-w", ewOut},
                               {L"write", ewOut}));
    // Self-created scratch tree is visible + recursively deletable.
    auto ewTree = Join(ew, L"treebase");
    MakeDirs(ewTree);
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"scratchtree", ewTree}));
    // Cross-process created-set: created in one process, read/deleted in another.
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"writespawnread", Join(ew, L"xproc.tmp"), ProbePath()}));
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"writespawndelete", Join(ew, L"xprocdel.tmp"), ProbePath()}));
    // Pre-existing undeclared sibling stays hidden from enumeration.
    EXPECT_EQ(kNotFound, RunProbeRaw(base, {L"enumfind", ew, L"a.txt"}));
    // Without --execroot-writable, creating a new file is still denied.
    EXPECT_EQ(kDenied, RunProbeRaw({L"--filter-inputs", L"-W", ew}, {L"write", Join(ew, L"nope.tmp")}));
}

// --- Cleanup-on-exit: undeclared scratch discarded after the tree exits --------
TEST_F(EnforceTest, CleanupOnExit) {
    auto cw = NewWorkspace();
    std::vector<std::wstring> base = {L"--filter-inputs", L"--execroot-writable", L"-W", cw};

    auto cwScratch = Join(cw, L"scratch.tmp");
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"write", cwScratch}));
    EXPECT_FALSE(Exists(cwScratch));
    EXPECT_TRUE(Exists(Join(cw, L"a.txt")));  // pre-existing undeclared preserved

    auto cwDir = Join(cw, L"scratchdir");
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"mkdir", cwDir}));
    EXPECT_FALSE(Exists(cwDir));

    // Cross-process: scratch created by a spawned child is discarded on exit too.
    auto cwChild = Join(cw, L"childscratch.tmp");
    EXPECT_EQ(kOk, RunProbeRaw(base, {L"spawn", ProbePath(), L"write", cwChild}));
    EXPECT_FALSE(Exists(cwChild));

    // Declared -w output (NOT in created-set) survives.
    auto cwOut = Join(cw, L"out.declared");
    EXPECT_EQ(kOk, RunProbeRaw({L"--filter-inputs", L"--execroot-writable", L"-W", cw, L"-w", cwOut},
                               {L"write", cwOut}));
    EXPECT_TRUE(Exists(cwOut));

    // Under -D (--sandbox_debug) the scratch is kept for inspection.
    auto cwDbg = Join(cw, L"dbgscratch.tmp");
    auto cwDbgLog = (TempRoot() / L"cleanup-debug.out").wstring();
    EXPECT_EQ(kOk, RunProbeRaw({L"--filter-inputs", L"--execroot-writable", L"-W", cw, L"-D", cwDbgLog},
                               {L"write", cwDbg}));
    EXPECT_TRUE(Exists(cwDbg));
}

}  // namespace
}  // namespace bsx
