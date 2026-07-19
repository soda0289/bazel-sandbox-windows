# Documentation index

This project is a standalone Windows process sandbox for Bazel, built on upstream
[Detours](https://github.com/microsoft/detours) plus a vendored native
DetoursServices engine, driven by a patched Bazel `windows-sandbox` strategy. Its
north star is behavioral parity with hermetic `linux-sandbox` / remote execution:
only *declared* inputs are visible, and no filename special-casing.

Start with the [top-level `README.md`](../README.md) for what the tool is and how
to build it. Use this folder for the deeper design, comparison, and testing docs.

## Start here

* **What behaves differently from `linux-sandbox`, and why** →
  [`sandbox-parity-findings.md`](sandbox-parity-findings.md). The running issue
  ledger: every concrete discrepancy found against `linux-sandbox`, its root
  cause, current status, and the test that pins it. Read this first when
  debugging a real-repo failure.
* **How the vendored engine is wired** →
  [`vendor-architecture.md`](vendor-architecture.md). The bootstrap↔hooks
  contract, the policy/report facade, and exactly which manifest flags and policy
  bits `BazelSandbox` actually uses from the vendored code.

## `design/` — how it's built and why

* [`detours-input-filtering.md`](design/detours-input-filtering.md) — the
  in-place, *subtractive* input-filtering design (`--filter-inputs`): why it's
  used instead of a constructive VFS, the Mode 1/2/3 parity mapping, Mechanisms A
  (undeclared reads → `NOT_FOUND`) and B (enumeration filtering), the
  `DeclaredInput` marker-bit fix for the execroot symlink forest, and the
  `--execroot-writable` write model. §9/§10 record the implementation log and
  test strategy.
* [`projfs-sandbox-modes.md`](design/projfs-sandbox-modes.md) — the *constructive*
  ProjFS VFS alternative and its sandbox modes. Deferred (slow/complex per the
  spike); kept as the reference for the constructive approach.
* [`detours-write-overlay-vfs.md`](design/detours-write-overlay-vfs.md) — research
  proposal for a Detours **write-redirection overlay** (per-action VFS) to close
  A8 and generalize A7/B2: redirect only *undeclared writes* into a private
  per-action backing store (temp/RAM disk) while reads stay on the real execroot.
  Includes a design study of [usvfs](https://github.com/ModOrganizer2/usvfs)
  (GPLv3 — study only), the write-only vs full-VFS analysis, the enumeration
  filter→insert problem, and the shared-memory overlay map. Recommends the cheap
  A8 no-clobber fix now; overlay as a later evolution; not the full read VFS.

## `comparison/` — parity reference points

* [`linux-sandbox-comparison.md`](comparison/linux-sandbox-comparison.md) — the
  architectural narrative and flag-by-flag map against Bazel's `linux-sandbox`:
  which flags are implemented, which are intentionally N/A on Windows, and which
  are worth adding.
* [`gsoc-proposal-comparison.md`](comparison/gsoc-proposal-comparison.md) — how
  this project relates to the original "Sandboxing on Windows" GSoC proposal and
  to Bazel's actual `windows-sandbox` CLI contract, including a feature table and
  the `-M`/`-m` bind-mount analysis.

## `e2e/` — end-to-end testing

* [`smoke-testing.md`](e2e/smoke-testing.md) — the differential smoke harness
  (`tests/e2e/smoke.ps1`) that builds real repos under both plain `local` and
  `windows-sandbox`, plus the results tables (regressions + timing).
* [`rules_js-windows-runfiles.md`](e2e/rules_js-windows-runfiles.md) — notes on
  the rules_js / runfiles behavior on Windows.

## `testing/` — test-suite architecture

* [`test-suite-migration.md`](testing/test-suite-migration.md) — proposal +
  migration plan for restructuring the tests: keep `probe.cpp` as the sandboxed
  child, port the PowerShell **enforce** suite to **GoogleTest** (`cc_test`, direct
  `CreateProcessW`, fixtures, parametrized cases), and split the **e2e** real-tool
  matrix into a hermetic lane (node/python/java/dotnet/uutils/pwsh7 via Bazel
  rules + `http_archive`) and an opt-in native-OS lane. Not started.
