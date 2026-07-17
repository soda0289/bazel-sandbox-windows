# Upstream opportunity: rules_js js_binary entry-point resolution on Windows (no runfiles)

**Status:** analysis + reproduction, ready to file upstream. Not yet reported to
`aspect-build/rules_js` (this repo's `gh` auth cannot search that repo; the search /
filing step is a follow-up).

This documents a **rules_js** (not sandbox) defect discovered by the
`windows-sandbox` differential smoke test (`docs/e2e/smoke-testing.md`). It only
manifests under hermetic execution (this sandbox, or RBE, or
`--experimental_use_hermetic_linux_sandbox`); a plain Windows `local` build masks it
via execroot leakage.

## Summary

When a `js_binary` is used as the **tool of a build action** (genrule,
`custom_rule`, `js_run_binary`, worker) and Bazel has **no runfiles symlink tree**
(the default on Windows, absent `--enable_runfiles`), the launcher resolves the
binary's **own entry point** through the caller-supplied `BAZEL_BINDIR`. For a tool
that is a cross-configuration dependency, `BAZEL_BINDIR` is the *caller's* config
(e.g. `fastbuild`), not the *tool's* config (`opt-exec`). The entry point lives in
the tool's own bindir, so resolution points at the wrong tree and the launcher
aborts:

```
FATAL: aspect_rules_js[js_binary]: the entry_point
'<execroot>/bazel-out/x64_windows-fastbuild/bin/<pkg>/<entry>.cjs' not found
```

The build only "works" on `local` because the same binary is often *also* built in
the caller's config elsewhere in the graph, leaving a copy at that path — an
undeclared input for this action. Under any input-filtering execution that copy is
absent, so the action fails.

## Where it is

`js/private/js_binary.sh.tpl`:

```sh
function resolve_execroot_bin_path {
    local short_path="$1"
    if [[ "$short_path" == ../* ]]; then
        echo "$JS_BINARY__EXECROOT/${BAZEL_BINDIR:-$JS_BINARY__BINDIR}/external/${short_path:3}"
    else
        echo "$JS_BINARY__EXECROOT/${BAZEL_BINDIR:-$JS_BINARY__BINDIR}/$short_path"
    fi
}
...
if [ "${JS_BINARY__USE_EXECROOT_ENTRY_POINT:-}" ] || [ "${JS_BINARY__NO_RUNFILES:-}" ]; then
    entry_point=$(resolve_execroot_bin_path "{{entry_point_path}}")
else
    entry_point="$JS_BINARY__RUNFILES/{{workspace_name}}/{{entry_point_path}}"
fi
```

`BAZEL_BINDIR` is intentionally the caller's `$(BINDIR)` — the launcher `cd`s into
it so *node module resolution* runs from the root of the caller's output tree. The
bug is that the **same** `BAZEL_BINDIR` is reused to locate the binary's **own**
entry point (and, by the same code path, its own data files), which belong to the
binary's config, not the caller's.

Note `resolve_execroot_bin_path` already carries the correct value as a fallback:
`$JS_BINARY__BINDIR` is baked into the launcher at build time and *is* the binary's
own bindir. It is simply shadowed by `BAZEL_BINDIR` whenever the caller sets it.

## Reproduction

```
git clone https://github.com/aspect-build/rules_js
cd rules_js/examples

# Linux (has a runfiles tree) — PASSES:
bazel build //js_binary:run1_cjs --spawn_strategy=linux-sandbox

# Windows (no runfiles tree) under any input-filtering sandbox — FAILS:
#   entry_point '<...>/x64_windows-fastbuild/bin/js_binary/require_acorn.cjs' not found
bazel build //js_binary:run1_cjs --spawn_strategy=<hermetic sandbox>

# Windows WITH a runfiles tree — PASSES:
bazel build //js_binary:run1_cjs --spawn_strategy=<hermetic sandbox> --enable_runfiles
```

`run1_cjs` is a genrule whose `cmd` invokes the `bin_cjs` js_binary tool and sets
`BAZEL_BINDIR=bazel-out/x64_windows-fastbuild/bin` (the genrule's own config).
`aquery //js_binary:run1_cjs` shows the declared inputs are the **opt-exec**
`bin_cjs.bat` + its `.runfiles` tree; the fastbuild `require_acorn.cjs` is not
declared.

## Candidate fixes (for upstream discussion)

1. **Resolve the binary's own entry point / data via `$JS_BINARY__BINDIR`, not
   `BAZEL_BINDIR`.** Keep `cd "$BAZEL_BINDIR"` for node's module-resolution root,
   but compute `entry_point` (and the binary's own runfiles/data) from the baked-in
   `$JS_BINARY__BINDIR`. This makes the no-runfiles path hermetic for cross-config
   tools. Needs validation that same-config invocations (where
   `BAZEL_BINDIR == JS_BINARY__BINDIR`) are unaffected, and that `js_run_binary`'s
   `use_execroot_entry_point` path is consistent.

2. **Declare the entry point (and data) in the caller's config.** Ensure that when a
   js_binary is a tool, its `copy_to_bin` outputs in the *caller's* config are
   propagated as declared inputs of the action. Heavier; may duplicate artifacts
   across configs.

3. **Documentation-only:** require `--enable_runfiles` for hermetic Windows builds.
   This is the current effective guidance and matches Bazel's Windows story, but it
   pushes a privilege requirement (Developer Mode) onto every consumer and does not
   fix the non-hermeticity of the no-runfiles path itself.

Option 1 is the most targeted and preserves the no-runfiles design intent; it is the
recommended proposal.

## Why this is not a sandbox bug

The `windows-sandbox` behaves exactly as hermetic linux-sandbox / RBE: it exposes
only declared inputs. The undeclared, cross-config `require_acorn.cjs` is hidden by
design. The differential harness flags it as a `pass-local / fail-sandbox` delta
precisely because `local` is non-hermetic here. Fixing it upstream (or enabling
runfiles) removes the delta without weakening enforcement.
