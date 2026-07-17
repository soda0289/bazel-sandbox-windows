@{
    # Curated repo presets for tests/e2e/smoke.ps1 (differential windows-sandbox
    # smoke testing). Each entry supplies defaults that the CLI can override.
    #
    #   RepoUrl        git URL to clone (shallow by default)
    #   Ref            branch/tag/commit to check out (optional; repo default if omitted)
    #   Subdir         sub-dir that is the actual Bazel workspace root (optional)
    #   Submodules     $true to recurse git submodules on clone (repos that keep
    #                  in-tree bzlmod modules as submodules, e.g. gitiles' jgit)
    #   Targets        target patterns to build (array)
    #   ExtraBuildArgs extra flags appended to BOTH the local and sandbox builds
    #
    # NOTE: --enable_runfiles=yes and --windows_enable_symlinks are NOT set per-preset
    # anymore - the harness applies both to BOTH phases by default (-EnableRunfiles /
    # -WindowsSymlinks, both default $true) so every repo gets hermetic-parity runfiles
    # trees materialized with real symlinks (matching linux-sandbox / RBE). Only put
    # repo-SPECIFIC flags in ExtraBuildArgs (e.g. --lockfile_mode=off for version drift).
    #
    # Triage rationale (see plan.md): the JS/TS ecosystem (rules_js / rules_ts /
    # Angular) is where every hard Windows-sandbox bug lives - pnpm intra-store
    # junctions, node package.json walk-up, symlink forests. Those are the high
    # signal presets. Bazel-self is a good native-toolchain dogfood. The giant
    # C++/ML repos (tensorflow, envoy, carbon-lang, distroless) are Linux-centric
    # and flaky on Windows, so they mostly measure "buildability tax" not sandbox
    # parity; kept here only as optional, heavyweight entries.

    # ---- Primary: JS/TS ecosystem (highest sandbox signal) -----------------

    # rules_js proof-of-concept. rules_js ships a single self-contained example
    # WORKSPACE at examples/ (one MODULE.bazel; the sub-dirs npm_deps, webpack_cli,
    # nextjs, rspack, vite*, worker, linked_*, etc. are PACKAGES of it, not separate
    # workspaces). So Subdir must be examples/ and `//...` builds the entire example
    # workspace in one run (~271 targets across ~23 packages) - do NOT point Subdir
    # at a package like examples/npm_deps: Bazel walks up to examples/ anyway and
    # `//...` is workspace-root-relative, so a package Subdir is just misleading.
    # These exercise pnpm-style node_modules with intra-store junctions - exactly
    # the symlink-forest / package.json-walk surface the sandbox has to get right.
    # (Runfiles-tree materialization + symlinks are harness-wide defaults now; see the
    # header note. Historically rules_js REQUIRED --enable_runfiles because without a
    # tree its js_binary launcher resolves entry points via the caller's BAZEL_BINDIR
    # cross-config path and relies on execroot leakage, which the sandbox/RBE deny -
    # see docs/e2e/rules_js-windows-runfiles.md.)
    rules_js = @{
        RepoUrl        = 'https://github.com/aspect-build/rules_js'
        Subdir         = 'examples'
        Targets        = @('//...')
    }

    # rules_js e2e/webpack_devserver: a SEPARATE, self-contained workspace (its own
    # MODULE.bazel under e2e/webpack_devserver) - net-new coverage vs examples/. Runs
    # a real webpack bundle + js_run_devserver graph. Validated clean (10/10 both-pass,
    # 0 regressions).
    rules_js_webpack_devserver = @{
        RepoUrl        = 'https://github.com/aspect-build/rules_js'
        Subdir         = 'e2e/webpack_devserver'
        Targets        = @('//...')
    }

    # rules_ts example workspace: tsc through the toolchain (declaration walking,
    # the picomatch/skipLibCheck family of resolution behaviours). Same layout as
    # rules_js - examples/ is the single workspace root (examples/simple etc. are
    # packages), so Subdir=examples/ and `//...` covers the whole example workspace.
    rules_ts = @{
        RepoUrl        = 'https://github.com/aspect-build/rules_ts'
        Subdir         = 'examples'
        Targets        = @('//...')
    }

    # Angular via rules_js - heavy ng_package / ngc surface. Scope to a subset of
    # packages rather than //... (the full repo is very large / slow).
    #
    # KNOWN-BLOCKED (as of this fork): angular/angular and angular/components `main`
    # pin Bazel 8.7.0 (.bazelversion) and set `common --incompatible_merge_fixed_and_
    # default_shell_env` in .bazelrc - a flag that was REMOVED in Bazel 9.x. Our
    # patched bazel-dev.exe is 9.1.1 (matches this repo's .bazelversion), so it
    # rejects that rc line at option-parsing and BOTH phases fail identically before
    # any action runs (0 sandbox signal). --lockfile_mode=off clears the separate
    # MODULE.bazel.lock-version error but not the rc-flag wall. To actually exercise
    # Angular we'd need to rebase the sandbox patch onto Bazel 8.7.0 (or sanitize the
    # repo .bazelrc). Kept here for when that happens.
    angular = @{
        RepoUrl        = 'https://github.com/angular/angular'
        Ref            = 'main'
        Targets        = @('//packages/core:core', '//packages/common:common')
        ExtraBuildArgs = @('--lockfile_mode=off')
    }

    angular_material = @{
        RepoUrl        = 'https://github.com/angular/components'
        Ref            = 'main'
        Targets        = @('//src/cdk:cdk', '//src/material/button:button')
        ExtraBuildArgs = @('--lockfile_mode=off')
    }

    # ---- Secondary: native-toolchain dogfood -------------------------------

    # rules_dotnet example workspace: exercises the .NET SDK toolchain (C#/F#
    # compilation, publish, runfiles) on Windows. examples/ is a single workspace
    # (one MODULE.bazel; basic_csharp, basic_fsharp, aspnetcore, publish_*,
    # runfiles_*, source_generators, paket, expecto, etc. are PACKAGES), so
    # Subdir=examples/ + `//...` builds them all. Good non-JS toolchain coverage
    # with real runfiles/publish output trees. Expect some both-fail on Windows for
    # platform-specific / self-contained-publish targets (not sandbox bugs).
    rules_dotnet = @{
        RepoUrl = 'https://github.com/bazel-contrib/rules_dotnet'
        Ref     = 'master'
        Subdir  = 'examples'
        Targets = @('//...')
    }

    # Bazel building a slice of itself - good C++/Java toolchain coverage without
    # the flakiness of the ML/C++ mega-repos. Scope to a small, fast tool.
    bazel_self = @{
        RepoUrl = 'https://github.com/bazelbuild/bazel'
        Ref     = 'master'
        Targets = @('//src/main/cpp/util:util')
    }

    # Full Bazel self-build (bazel-builds-bazel). Large (~6,651 actions, ~1,264 Javac
    # actions sandboxed) but the highest-value native dogfood: it stresses the
    # cross-process created-set (JavaBuilder writes _javac scratch in one process and
    # reads/cleans it in another) and discard-on-exit cleanup end to end. Validated
    # GREEN with 0 sandbox-class failures; sandbox overhead was ~0 (see
    # docs/e2e/smoke-testing.md). Slow (~65 min/phase) - run deliberately, not in a
    # quick loop.
    bazel_self_full = @{
        RepoUrl = 'https://github.com/bazelbuild/bazel'
        Ref     = 'master'
        Targets = @('//src:bazel')
    }

    # ---- New Bazel-9 candidates (confirmed .bazelversion 9.x, bzlmod) ------------

    # GerritCodeReview/gitiles - pure-Java servlet library (Git repo browser). BEST
    # next candidate: .bazelversion 9.1.0 (matches our fork's major.minor), pure
    # bzlmod (MODULE.bazel + lock), small (~50 Java files), clean dep graph
    # (rules_java 9.3.0 + rules_jvm_external 7.0 + JDK toolchain, no Go/Android/shell
    # in the hot path). Exercises the Java compile+jar toolchain on a NON-bazel repo.
    # Two one-time Windows overrides: --workspace_status_command= skips the repo's
    # python3 ./tools/workspace_status.py (python3 need not be on PATH), and
    # --lockfile_mode=off avoids friction from a lockfile committed on Linux (the
    # Windows module-extension outputs differ). Target = the main servlet library.
    gitiles = @{
        RepoUrl        = 'https://github.com/GerritCodeReview/gitiles'
        Ref            = 'master'
        Submodules     = $true
        Targets        = @('//java/com/google/gitiles:servlet')
        ExtraBuildArgs = @('--workspace_status_command=', '--lockfile_mode=off')
    }

    # abseil/abseil-cpp - canonical Bazel C++ library. Pure bzlmod, NO .bazelversion
    # pin (open to any Bazel >=7) and NO committed MODULE.bazel.lock (zero lockfile
    # friction on Windows); minimal deps (rules_cc, bazel_skylib, platforms,
    # googletest), and an explicit x64_windows-clang-cl platform in BUILD.bazel.
    # Different toolchain axis than gitiles (native C++ compile+static-lib link under
    # MSVC). Scope to a representative slice, not //... (hash/debugging pull in
    # platform assembly). For the Clang-CL path add --platforms=//:x64_windows-clang-cl.
    abseil = @{
        RepoUrl = 'https://github.com/abseil/abseil-cpp'
        Ref     = 'master'
        Targets = @('//absl/strings:strings', '//absl/base:base', '//absl/container:flat_hash_map')
    }

    # SeleniumHQ/selenium - multi-language (Java/TS/Py/Ruby/Rust/.NET). .bazelversion
    # 9.1.0, bzlmod, and it HAS Windows CI (.github/workflows/ci-java.yml
    # browser-tests-windows) plus --windows_enable_symlinks + --enable_runfiles baked
    # into its .bazelrc. Usable but heavy: 30+ bazel_deps and a ~200-artifact Maven
    # graph resolved on first build, and it targets JDK 25 (remotejdk_25 download).
    # Scope to a leaf Java library with no browser drivers / native code.
    selenium = @{
        RepoUrl = 'https://github.com/SeleniumHQ/selenium'
        Ref     = 'trunk'
        Targets = @('//java/src/org/openqa/selenium:core')
    }

    # GerritCodeReview/gerrit - large multi-language repo (.bazelversion 9.1.0,
    # bzlmod) with rules_android + rules_go + an external git_override bazlets dep.
    # Too heavy to build wholesale, but a TINY pure-Java leaf compiles fine and still
    # exercises the full bzlmod + rules_jvm_external + rules_java (JDK 25) path:
    # //java/com/google/gerrit/common:annotations is 3 explicitly-named pure-@interface
    # files (Nullable/UsedAt/ConvertibleToProto) with a single //lib:guava dep, no
    # annotation processors, no Guice, no JGit, no proto codegen. NOTE: the first build
    # still resolves gerrit's full @external_deps Maven graph (rules_jvm_external
    # downloads the whole declared set once) - unavoidable for any //lib: dep, cached
    # thereafter. --workspace_status_command= skips gerrit's python3 status script;
    # --lockfile_mode=off avoids Windows lockfile-extension friction.
    gerrit = @{
        RepoUrl        = 'https://github.com/GerritCodeReview/gerrit'
        Ref            = 'master'
        Targets        = @('//java/com/google/gerrit/common:annotations')
        ExtraBuildArgs = @('--workspace_status_command=', '--lockfile_mode=off')
    }

    # ---- Investigated but NOT Bazel-9 usable (do not enable without work) --------
    #
    #   envoyproxy/envoy        BLOCKED - .bazelversion 8.7.0; .bazelrc forces
    #                           --noenable_bzlmod + --enable_workspace and uses
    #                           --incompatible_merge_fixed_and_default_shell_env
    #                           (removed in Bazel 9). Pure Linux/macOS C++ CI.
    #   carbon-language/carbon-lang  BLOCKED - .bazelversion 8.6.0; custom Clang-only
    #                           toolchain; CI has no Windows runner.
    #   cert-manager/cert-manager    NOT A BAZEL PROJECT - Make/Go (go.mod), no
    #                           MODULE.bazel/WORKSPACE/BUILD. Not smoke-testable here.

    # ---- Optional heavyweight (Linux-centric; low sandbox signal) ----------
    # KNOWN-BLOCKED: repo HEAD is not Bazel-9-compatible - BUILD files use native
    # sh_binary/sh_test (removed in Bazel 9; now need @rules_shell loads) and pin an
    # old rules_go that breaks on Bazel 9's module-extension API ('Facts' has no
    # 'clear'). Both phases fail identically at loading (0 targets, 0 processes) =>
    # zero sandbox signal. Would need the repo patched for Bazel 9 to test.
    distroless = @{
        RepoUrl = 'https://github.com/GoogleContainerTools/distroless'
        Targets = @('//...')
    }
}
