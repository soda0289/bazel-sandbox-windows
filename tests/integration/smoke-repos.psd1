@{
    # Curated repo presets for tests/integration/smoke.ps1 (differential windows-sandbox
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

    # ---- jgit / gitiles (POSIX-shell genrules; NOW BUILDABLE on Windows) --------
    # jgit was long "blocked" on this Windows host; it is NOW GREEN both local AND
    # windows-sandbox (0 regressions) with the recipe below. The failures were never
    # sandbox bugs (they reproduced identically under plain --spawn_strategy=local).
    # Kept as presets - jgit is a good heavy Java+genrule sandbox exercise (msys
    # process spawning, thousands of per-file touch, mktemp temp dirs, coursier fetch).
    #
    # ROOT CAUSE (corrected after end-to-end Bazel repro): jgit runs POSIX-shell
    # genrules that need a COHERENT msys2 toolchain (mktemp/unzip/find/touch/zip):
    #   //org.eclipse.jgit:jgit  ->  mktemp -d; unzip; find . -exec touch -t ...; zip
    # This genrule fails with GNU find's "find: 'touch': No such file or directory".
    # (jgit ALSO ships a bazlets transform_srcjar rule - reached only by the .ee8
    # servlet bridge, and hence by gitiles, NOT by //org.eclipse.jgit:jgit - which
    # fails the SAME WAY but for a DIFFERENT root cause; see the gitiles section.)
    #
    # It is NOT a ';'-vs-':' separator bug (msys2 converts PATH correctly) and NOT a
    # sandbox bug (fails identically under plain --spawn_strategy=local). The real cause
    # is PATH COMPOSITION. Bazel runs genrules via BAZEL_SH (C:\msys64\usr\bin\bash.exe)
    # as a NON-login `bash -c`, which does NOT source /etc/profile, so msys2 /usr/bin is
    # NOT auto-prepended. jgit's .bazelrc forces --incompatible_strict_action_env +
    # --action_env=PATH, so the genrule's PATH is exactly the forwarded Windows client
    # PATH. A typical Windows box has NO msys2 /usr/bin on that PATH, but DOES have
    # competing PARTIAL toolchains: uutils-coreutils (C:\Program Files\coreutils\bin),
    # Git's usr\bin, and Windows' own System32\find.exe (which has find but no touch).
    # So `find` resolves to a GNU find whose execvp("touch") searches a PATH with no
    # reachable `touch` -> the error. Proven: with msys2 /usr/bin FIRST on the action
    # PATH, find+touch are co-located and the genrule SUCCEEDS; with System32-only it
    # dies (Exit 127, POSIX tools missing).
    #
    # PROVEN FIX / FULL RECIPE (jgit builds GREEN local+sandbox with all of these):
    #   1. --action_env=PATH=C:\msys64\usr\bin;<JDK17\bin>;<rest-of-PATH>
    #      msys2 /usr/bin FIRST = one coherent POSIX toolchain (find+touch+unzip+zip+
    #      mktemp all co-located). This is THE genrule fix. Keep JDK17 + rest so
    #      coursier still finds a JDK (see step 2). Machine-specific (msys path).
    #   2. JAVA_HOME=<JDK17> and put <JDK17>\bin AHEAD of any JRE (e.g. Zulu-8) on the
    #      host PATH: rules_jvm_external's coursier fetch runs `java @argsfile`, which
    #      needs Java 9+ (@argfile support). A JRE-8 default -> "Could not find or load
    #      main class @...java_argsfile".
    #   3. --config=java21  (jgit ships this config): our master-built bazel bundles a
    #      Java-21 BazelJavaBuilder (class file v65); jgit's .bazelrc pins the tool
    #      runtime to remotejdk_17 (max v61) -> UnsupportedClassVersionError. java21
    #      bumps all four java version knobs to 21.
    #   4. --workspace_status_command=<cmd that prints "STABLE_BUILD_JGIT_LABEL <v>">.
    #      genrule-setup.sh enables `set -e -o pipefail`; the genrule does
    #      GEN_VERSION=$(cat stable-status.txt | grep -w STABLE_BUILD_JGIT_LABEL | ...).
    #      If the label is absent, grep exits 1 -> pipefail -> set -e ABORTS the genrule
    #      (Exit 1). (An EMPTY --workspace_status_command= does NOT work - earlier note
    #      that it "tolerates an empty label" was wrong.) A one-line .bat that echoes
    #      "STABLE_BUILD_JGIT_LABEL v0.0.0-dev" is enough.
    #   5. --lockfile_mode=off (Linux-generated committed MODULE.bazel.lock) and, on a
    #      corporate-proxy host, JAVA_TOOL_OPTIONS + -HostJvmArgs trustStore=Windows-ROOT
    #      so ALL JVMs (bazel server + coursier fetcher) trust the Windows cert store.
    # NB the genrule is SLOW on Windows (~240s): `find . -exec touch ... ';'` spawns one
    # touch process per file over ~3k files. Correct, just slow.

    # eclipse-jgit/jgit - pure-Java Git implementation, .bazelversion 9.0.1, bzlmod.
    # //org.eclipse.jgit:jgit is the manifest-stamp genrule (minimal, no bazlets /
    # servlet-transform needed). MODULE deps: rules_java 9.3.0, rules_jvm_external 6.10,
    # rules_shell, rules_go, rules_android, bazel_features, rbe_autoconfig.
    # RESULT: GREEN both local (399.5s) + windows-sandbox (344.9s), 0 regressions.
    #
    # The ExtraBuildArgs below are the PORTABLE flags. You MUST ALSO pass the two
    # machine-specific pieces at runtime (they encode local paths):
    #   -ExtraBuildArgs @('--config=java21','--lockfile_mode=off',
    #                     '--workspace_status_command=C:\path\to\ws_status.bat',
    #                     "--action_env=PATH=C:\msys64\usr\bin;<JDK17>\bin;$env:PATH")
    # and set $env:JAVA_HOME=<JDK17>; $env:PATH="C:\msys64\usr\bin;<JDK17>\bin;$env:PATH"
    # (see the FULL RECIPE comment above). ws_status.bat = one line:
    #   @echo STABLE_BUILD_JGIT_LABEL v0.0.0-dev
    jgit = @{
        RepoUrl        = 'https://github.com/eclipse-jgit/jgit'
        Ref            = 'master'
        Targets        = @('//org.eclipse.jgit:jgit')
        ExtraBuildArgs = @('--config=java21', '--lockfile_mode=off')
    }

    # GerritCodeReview/gitiles - pure-Java servlet library (Git repo browser),
    # .bazelversion 9.1.0, bzlmod, ~50 Java files. //java/com/google/gitiles:servlet
    # depends on //lib:jgit-servlet -> @jgit//org.eclipse.jgit.http.server.ee8 (the
    # javax/EE8 bridge) and on the jgit stamp genrule. jgit is a git SUBMODULE here
    # (local_path_override path="modules/jgit"), hence Submodules. gitiles' .bazelrc
    # ALREADY defaults to java21 (java_*_version=21), so do NOT pass --config=java21
    # (that config is undefined in gitiles and errors); java21 is implicit.
    #
    # RESULT: GREEN both local (465.8s) + windows-sandbox (391s), 0 regressions
    # (sandbox 0.84x). Needs the shared jgit runtime pieces (msys2-first
    # --action_env=PATH, JAVA_HOME/JDK17, workspace_status_command) PLUS two fixes:
    #
    #  (a) transform_srcjar (bazlets servlet_transform.bzl, reached via the ee8
    #      bridge) is a `ctx.actions.run_shell` that does NOT set
    #      use_default_shell_env=True, so the action gets NO PATH at all - and
    #      --action_env can only reach actions that DO opt into the default shell env.
    #      With no PATH, `find` still runs (bash's built-in default lookup) but its
    #      -exec child `touch` cannot be located -> "find: 'touch': No such file or
    #      directory". Breaks ONLY on Windows (Linux actions get a default
    #      /bin:/usr/bin). This is a genuine upstream jgit Windows-portability bug;
    #      the msys2-first --action_env=PATH pin does NOT fix it. FIX: add
    #      `use_default_shell_env = True` to that run_shell. For the smoke run we
    #      persist the one-line patch via --override_repository pointing at a patched
    #      copy of the bazlets repo (canonical name
    #      jgit++git_repository+com_googlesource_gerrit_bazlets).
    #  (b) errorprone toolchain drift: our master-built bazel bundles a stricter
    #      errorprone that promotes [NullArgumentForNonNullParameter] to an ERROR
    #      against gitiles source (Revision.java, LogServlet.java, ...). Relax with
    #      --javacopt=-Xep:NullArgumentForNonNullParameter:WARN.
    #
    # gitiles' own workspace_status.py emits STABLE_BUILD_GITILES_LABEL +
    # STABLE_BUILD_<submodule>_LABEL (incl. JGIT) via `git describe`, but relies on the
    # flaky Windows-Store python3 shim; override it with a deterministic .bat that
    # echoes STABLE_BUILD_GITILES_LABEL / STABLE_BUILD_JGIT_LABEL / _JAVA-PRETTIFY_.
    # The ExtraBuildArgs below are PORTABLE; also pass at runtime (machine-specific):
    #   --action_env=PATH=C:\msys64\usr\bin;<JDK17>\bin;$env:PATH
    #   --action_env=JAVA_HOME=<JDK17>
    #   --workspace_status_command=C:\path\to\gitiles_ws_status.bat
    #   --override_repository=jgit++git_repository+com_googlesource_gerrit_bazlets=<patched bazlets>
    gitiles = @{
        RepoUrl        = 'https://github.com/GerritCodeReview/gitiles'
        Ref            = 'master'
        Submodules     = $true
        Targets        = @('//java/com/google/gitiles:servlet')
        ExtraBuildArgs = @('--lockfile_mode=off', '--javacopt=-Xep:NullArgumentForNonNullParameter:WARN')
    }

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
