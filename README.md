# bazel-sandbox-windows

A standalone Windows process sandbox that reproduces the `BazelSandbox`
launcher (`Public/Src/BazelSandbox/Program.cs`) **without** the BuildXL
managed/C# stack.

It intercepts Windows file-system APIs with [Detours](https://github.com/microsoft/Detours)
to enforce a per-process file-access policy: it can make the whole file system
read-only, block a working directory, and selectively grant read / read-write /
no access to individual files and directories. This is exactly what a build
system such as Bazel needs to sandbox build actions on Windows.

### Origin

`BazelSandbox` is **not** part of Microsoft's BuildXL. It was written by
**Rong Jie Loo** (`rongjiecomputer`) during **Google Summer of Code 2018** as a
thin launcher on top of BuildXL's existing `DetoursServices` engine, and lives
in a fork of BuildXL:
[rongjiecomputer/BuildXL](https://github.com/rongjiecomputer/BuildXL). The goal
was to give Bazel a `windows-sandbox` (invoked via
`--experimental_windows_sandbox_path`), analogous to the existing
`linux-sandbox`. The design and rationale are set out in the GSoC proposal,
["Sandboxing on Windows"](https://docs.google.com/document/d/1ygpKUM_DwQDH9NX31p1MJlLGaYRzImCFD4F0rdvMqZk/edit).

This project takes that idea and re-grounds it on **stock, upstream components**:
it keeps the `DetoursServices` enforcement engine (which *does* originate in
Microsoft's [microsoft/BuildXL](https://github.com/microsoft/BuildXL)) but builds
it against public upstream Detours and drops all managed code. For a detailed
comparison to the GSoC proposal and to Bazel's actual `windows-sandbox` CLI
contract, see [`docs/gsoc-proposal-comparison.md`](docs/gsoc-proposal-comparison.md).

## How it works

The heavy lifting is done by the native **DetoursServices** enforcement engine
that ships in [microsoft/BuildXL](https://github.com/microsoft/BuildXL). This
project vendors that engine unchanged and builds it against **stock upstream
Detours** (not BuildXL's private Detours fork), plus a small native
reimplementation of BuildXL's C# `FileAccessManifest` serializer so no managed
code is required.

Two binaries are produced:

| Binary                | Role |
|-----------------------|------|
| `DetoursServices.dll` | The hook DLL injected into every sandboxed child. Contains the ~70 detoured file-system APIs and the policy-search engine. |
| `BazelSandbox.exe`     | The launcher. Parses options, builds the file-access manifest, and injects the DLL into a suspended child using **upstream Detours directly** (`DetourCreateProcessWithDllEx` + `DetourCopyPayloadToProcess`), then waits for it. No BuildXL code is linked into the launcher. |

### What was reimplemented vs. vendored

* **Vendored** (`vendor/detours-services/`): the DetoursServices C++ engine from
  BuildXL — the detoured functions, `PolicySearch`, `CanonicalizedPath`,
  `DetouredProcessInjector`, `StringOperations`, etc. Kept essentially verbatim;
  the only local additions are two small hooks that call into
  `src/network_detours.*` (attach the Winsock detours at DLL load, and deny
  `\Device\Afd` socket creation under `-n`). The exact upstream commit, the full
  list of files, and the two-file diff are recorded in
  [`vendor/PROVENANCE.md`](vendor/PROVENANCE.md) (+ `vendor/detours-services.patch`).
* **Network sandboxing** (`src/network_detours.{h,cpp}`): the `-N`/`-n` Winsock
  detours (built as a separate static lib so it can include `<winsock2.h>`
  before `<windows.h>`).
* **Vendored** (`vendor/sandbox-common/`): the handful of shared BuildXL headers
  the engine needs (`ReportType.h`, ...).
* **Reimplemented natively** (`src/manifest_builder.{h,cpp}`): BuildXL's C#
  `FileAccessManifest` blob serializer, including the open-addressing path
  hash-tree the DLL searches at runtime. The path hash (FNV-1 over normalized
  UTF-16) is reimplemented locally to match the engine's `NormalizeAndHashPath`
  byte-for-byte, so the launcher links no BuildXL code at all.
* **Launcher** (`src/main.cpp`): option parsing ported from BuildXL's
  `SandboxOption.cs`, manifest construction ported from `SandboxedProcess.cs`
  `CreateManifest`, and injection done with upstream Detours directly. Before
  copying, the manifest is wrapped in the small header the DLL expects
  (`[u32 size][u32 handleCount][u64 handles...][manifest]`); the three required
  handles (device map, remote-injection pipe, report pipe) are null since none
  of those features are used.
* **Compatibility shim** (`src/detours_compat.h`): BuildXL's Detours fork adds a
  one-time `DetourInit()`; upstream Detours initializes lazily, so this is a
  no-op that lets the vendored engine link against stock Detours.

### Intentionally dropped

* **DeviceMap** — Microsoft-internal-only NT DOS-device-map path virtualization
  (gated behind `FEATURE_DEVICE_MAP`, left undefined). `DeviceMap.cpp` compiles
  to an empty translation unit.
* **Reporting / report pipe** — by default `BazelSandbox` runs with reporting
  off; the sandbox purely *enforces* (denies unexpected accesses). Reporting can
  be turned on for debugging with `--trace <file>` (see [Debugging: `-D` and
  `--trace`](#debugging--d-and---trace)); we use the DLL's report-*path* mode
  (the DLL opens the file itself) rather than BuildXL's report *pipe*, so there
  is still no report pipe, injector pipe, or device map.
* **Timestamp faking** — BuildXL's engine can normalize input-file timestamps to
  a well-known value (`NormalizeReadTimestamps`, exercised by its `Timestamps`
  DetoursTest) so build outputs are deterministic. The launcher does **not** set
  that flag (see `src/main.cpp`), so sandboxed children observe files' **real**
  timestamps. It is a build-determinism feature, not a sandboxing one, and is not
  needed for Bazel (which does its own input hashing).
* **utf8proc** — a macOS-only dependency of the engine, never used on Windows.
  On Windows the engine's paths are UTF-16 (`wchar_t`) end to end and case
  folding uses `_towupper_l` with the invariant locale, exactly as in BuildXL;
  utf8proc is only referenced under `MAC_OS_LIBRARY`/`MAC_OS_SANDBOX`. Dropping
  it therefore changes nothing on Windows. (One consequence of the invariant
  `_towupper_l` — non-ASCII case-insensitivity — is characterized under
  [Known limitations](#known-limitations); it is inherited from BuildXL, not a
  result of dropping utf8proc.)

For a detailed map of how the vendored engine is wired together — the
bootstrap↔hooks contract, the policy/report facade, and exactly which
manifest flags and policy bits `BazelSandbox` actually uses — see
[`docs/vendor-architecture.md`](docs/vendor-architecture.md).

For how this project relates to the original "Sandboxing on Windows" GSoC
proposal and to Bazel's actual `windows-sandbox` CLI contract — including a
feature parity table and an analysis of `-M`/`-m` bind mounts — see
[`docs/gsoc-proposal-comparison.md`](docs/gsoc-proposal-comparison.md).

For a flag-by-flag comparison with Bazel's `linux-sandbox` — which flags are
implemented, which are intentionally not applicable on Windows, and which are
worth adding (notably `-C` resource limits) — see
[`docs/linux-sandbox-comparison.md`](docs/linux-sandbox-comparison.md).

For the design of the **in-place input-filtering path** — the `--filter-inputs`
default that makes undeclared inputs invisible (matching hermetic
`linux-sandbox` / remote execution), the mode mapping, the `--execroot-writable`
model, and the `DeclaredInput` marker-bit fix for the execroot symlink
forest — see [`docs/detours-input-filtering.md`](docs/detours-input-filtering.md).

## Building

Requirements: Windows x64, Visual Studio 2022+ (MSVC), and
[Bazelisk](https://github.com/bazelbuild/bazelisk) (a `.bazelversion` pins the
Bazel release). MSYS2 — which Bazel already requires on Windows — must be
installed and its `usr\bin` on `PATH` (see the note below).

```powershell
# Fetches upstream Detours from GitHub automatically (pinned commit + sha256).
bazel build //...
```

This produces `BazelSandbox.exe` and its injected `DetoursServices.dll` in
`bazel-bin/` (co-located; the launcher loads the DLL from its own directory at
runtime). Bump the Detours version by editing the `http_archive` commit +
`sha256` in `MODULE.bazel`.

Two environment notes are baked into `.bazelrc`:

* **Corporate TLS proxies** — a `startup --host_jvm_args` flag makes Bazel's JVM
  trust the Windows certificate store, so fetching the registry / archives does
  not fail with a PKIX TLS error behind a TLS-inspecting proxy.
* **MSYS2 on `PATH`** — the `rules_powershell` toolchain runs `chmod +x pwsh.exe`
  through bash while fetching PowerShell; `.bazelrc` inherits the client `PATH`
  for repository rules so MSYS2's `chmod` (`C:\msys64\usr\bin`) resolves. Put
  MSYS2's `usr\bin` on your `PATH`, or override it in a `user.bazelrc`.

> **Note:** the build is pinned to the *static release* CRT (`/MT`). This is
> required twice over: DetoursServices refuses to link a DLL CRT (it would get
> loaded into detoured processes), and using the *release* runtime guarantees
> `_DEBUG` is undefined so the manifest blob format matches between the builder
> and the DLL parser.

## Integrating with Bazel

`BazelSandbox.exe` is a standalone launcher — you can run it directly (see
[Usage](#usage)) — but to drive it *from Bazel* as the `windows-sandbox` spawn
strategy you currently need a **patched Bazel**. Upstream Bazel ships an
incomplete `windows-sandbox` runner (it only passes `-r`/`-w`/`-b`/`-D`, rejects
runfiles symlink trees, and never enables input-filtering / execroot-writable /
output-dir / network flags), so it cannot reach parity with `linux-sandbox` /
remote execution on its own.

[`integration/bazel-windows-sandbox.patch`](integration/bazel-windows-sandbox.patch)
completes that runner (Java host only, no filename special-cases). It targets a
**recent Bazel `master`** (verified at commit `a987dfc`, 2026-07-16; it uses the
post-9.x `SandboxOptions` getter API and does **not** apply to the `9.1.1`
release tag). In short:

```powershell
# 1. Build this repo's launcher + DLL.
bazel build //...

# 2. Patch + build Bazel itself (recent master, not the 9.1.1 tag).
git clone https://github.com/bazelbuild/bazel; cd bazel
git checkout a987dfc9d1474455305b82c69ea04d4bb2fb49a2   # verified; or a nearby master
git apply --3way C:\path\to\bazel-sandbox-windows\integration\bazel-windows-sandbox.patch
bazel build //src:bazel
Copy-Item bazel-bin\src\bazel.exe C:\tmp\bazel-dev.exe

# 3. Build your workspace under the sandbox with the patched Bazel.
C:\tmp\bazel-dev.exe build //... `
  --spawn_strategy=windows-sandbox,local `
  --experimental_use_windows_sandbox=yes `
  --experimental_windows_sandbox_path=C:\path\to\bazel-sandbox-windows\bazel-bin\BazelSandbox.exe `
  --enable_runfiles=yes
```

See [`integration/README.md`](integration/README.md) for the full patch
breakdown, flag reference, and `--windows_enable_symlinks` guidance, and
[`docs/e2e/smoke-testing.md`](docs/e2e/smoke-testing.md) for the differential
test harness that exercises this against real repos.

## Usage

```
BazelSandbox [option...] -- command [arg...]

  -W <dir>   working directory (default: current directory)
  -T <secs>  timeout after which the child is terminated
  -t <secs>  grace period before force kill after timeout
  -l <file>  redirect stdout to a file
  -L <file>  redirect stderr to a file
  -w <path>  make a file/directory read/writable in the sandbox
  -r <path>  make a file/directory read-only in the sandbox
  -b <path>  make a file/directory inaccessible in the sandbox
  -d <path>  reveal an output's parent dir (allow mkdir/write on the dir
             itself; its undeclared contents stay hidden)
  -N         allow only loopback network access (block external)
  -n         block all network access (no loopback either)
  -H         hermetic reads: deny the working dir by default (default: reads
             unconfined like the default linux-sandbox; writes still need -w)
  --filter-inputs  strict mode: implies -H and makes undeclared inputs
             invisible (denied reads return NOT_FOUND, directory listings hide
             undeclared entries) - matches hermetic linux-sandbox / remote exec
  --execroot-writable  allow creating NEW files/dirs anywhere in the working
             dir (and re-writing files created this run) while still denying
             overwrites of pre-existing undeclared/input files
  -D <file>  write launcher diagnostics to a file
  --trace <file>  write a per-access report (from the sandbox DLL) to a file
  -S <file>  write child resource-usage statistics (protobuf) to a file
  @FILE      read newline-separated arguments from FILE (until the first --)
  --         command to run in the sandbox, followed by its arguments
```

### Policy model

By default the sandbox makes the **entire file system read-only**, matching the
default `linux-sandbox` ("the entire filesystem is made read-only"): reads are
**not** confined to declared inputs, and only **writes** are restricted. The tool
being launched is granted read access automatically. Callers then open up
exactly the paths an action needs to **write**:

* `-r <path>` grants read-only access to a file or directory subtree. (Redundant
  in the default permissive mode, where reads are already allowed; required under
  `-H`/`--filter-inputs`.)
* `-w <path>` grants read-write access.
* `-b <path>` blocks a file or directory subtree (overrides read access too).
* `-d <path>` reveals a declared **output's parent directory**: a node-only grant
  so the tool can `stat`/enumerate it and its recursive `mkdir` succeeds, while
  the directory's subtree stays denied (undeclared files inside it remain hidden
  and unwritable). Mirrors `linux-sandbox` pre-creating output parent dirs.
* `-H` switches to **hermetic reads**: the working directory is denied by
  default, so only `-r`/`-w` inputs are readable. This is the Windows analog of
  Bazel's `--experimental_use_hermetic_linux_sandbox` and enforces read
  hermeticity for Goal-2 builds. Writes are confined to `-w` in both modes.

Scopes are hierarchical and later/more-specific scopes override broader ones, so
e.g. `-w outdir -b outdir\secret.txt` makes `outdir` writable while keeping
`secret.txt` inaccessible.

### Input filtering (`--filter-inputs`) — the `windows-sandbox` default

The Bazel `windows-sandbox` spawn strategy runs actions **in place in the real
execroot** (there is no throwaway symlink forest, unlike `linux-sandbox`) and
passes `--filter-inputs` on every spawn. This turns the sandbox **subtractive**
so that it reaches the same practical isolation as **hermetic `linux-sandbox` /
remote execution (RBE)** — where only *declared* inputs are visible — without
building any virtual filesystem:

* `--filter-inputs` implies `-H` (execroot denied by default; only `-r`/`-w`
  grants are visible) and additionally makes undeclared inputs **invisible**:
  denied reads of an existing-but-undeclared path report **`NOT_FOUND`** (not
  `ACCESS_DENIED`), and undeclared entries are **removed from directory
  enumerations**. So an undeclared file looks *absent*, exactly as it would under
  Linux's symlink forest. There is **no filename special-casing** — visibility is
  decided purely by whether Bazel declared the path as an input to this action.
* `--execroot-writable` matches `linux-sandbox`'s fully-writable throwaway
  execroot: the tool may **create** new files/dirs anywhere in the working dir
  and re-write files it created this run, while still **denying overwrites** of
  pre-existing undeclared/input files. This covers tools that write undeclared
  scratch inside the execroot (e.g. vite's `node_modules/.vite-temp`) without
  opening a hole to clobber real inputs.

Because the action runs in place, declared inputs reached through the execroot's
per-entry symlink forest (each `_main/*` entry is a symlink/junction into the
real workspace) are rescued by a policy **marker bit**
(`FileAccessPolicy_DeclaredInput`): it is OR'd only into explicit `-r`/`-w`/
`-d`/tool grants, never the whole-disk read baseline, so a denied
symlink/junction read is allowed **only** when its resolved target is a declared
input — closing the leak where undeclared workspace files were reachable via the
baseline read grant. This whole design (mode mapping, the subtractive behaviors,
and the marker-bit fix) is specified in
[`docs/detours-input-filtering.md`](docs/detours-input-filtering.md).

### Network sandboxing

Mirroring Bazel's Linux sandbox `-N`/`-n` flags, network access can be
restricted:

* `-N` allows **only loopback** (`127.0.0.0/8`, `::1`, and `localhost` name
  resolution); connections to any external address are blocked.
* `-n` blocks **all** network access, loopback included.

Enforcement is implemented by detouring Winsock (`connect`, `WSAConnect`,
`sendto`, `WSASendTo`, `bind`, `getaddrinfo`/`GetAddrInfoW`, `gethostbyname`) in
the injected DLL. Under `-n` we additionally deny opening the `\Device\Afd`
socket device in the `NtCreateFile`/`ZwCreateFile` hooks, so even code that
bypasses `ws2_32` and talks to AFD directly cannot create a socket. Like the
file policy, the network policy propagates to the whole process tree (it is
carried in an inherited `BAZEL_SANDBOX_NETWORK` environment variable).

This is a **cooperative, per-process** boundary (the same trust model as the
file-access enforcement): it reliably contains build actions that reach the
network accidentally. Because `-N` must let sockets be created for loopback, its
external block lives at the Winsock connect layer rather than at AFD; a
determined process could still craft raw AFD IOCTLs. For a hostile-code-grade
boundary, a kernel-enforced mechanism (WFP, AppContainer) would be required.

### Debugging: `-D` and `--trace`

Two optional flags help diagnose sandbox problems. They are independent and can
be used together.

* **`-D <file>`** writes **launcher-side diagnostics** — what *the sandbox
  wrapper* did: the resolved working directory, tool, and DLL paths, the network
  policy, each manifest policy scope (`scope na/ro/rw: <path>`), the manifest
  size, the child PID, and the child's exit code (or a timeout/failure note).
  This mirrors Bazel's `linux-sandbox -D <file>` (which likewise records the
  sandbox's own setup). It does **not** record the child's file accesses.

* **`--trace <file>`** writes a **per-access report** — what the *sandboxed
  process* (and every descendant) touched. This turns on the vendored engine's
  reporting channel (otherwise fully inert): the launcher sets the report flags
  and names the file in the manifest, and the injected DLL opens it and appends
  one line per intercepted operation. It is the fastest way to answer "why was
  this access denied?". Enabling it does **not** change enforcement decisions —
  it only adds logging.

  The launcher truncates the trace file at startup; the DLL then appends. Output
  is BuildXL's native report-line format, encoded as **UTF-16LE** (no BOM). Each
  file-access line looks like:

  ```
  <type>,<Operation>:<pid>|<id>|<corrId>|<access>|<status>|<explicit>|<error>|<rawError>|<usn>|<desiredAccess>|<shareMode>|<creationDisposition>|<flagsAndAttributes>|<openedAttrs>|<pathId>|<path>|<filter>
  ```

  The most useful fields are `Operation` (e.g. `CreateFile`,
  `GetFileAttributes`), `access` (the requested access class), `status`
  (`1`=allowed, `2`=denied), and the final `path`. Because reports arrive from
  every process in the tree appending to one file, lines from concurrent
  grandchildren can interleave; treat `--trace` as a debugging aid, not a
  machine-parsed audit log.

### Resource statistics: `-S`

`-S <file>` writes the child's resource usage to `<file>` as a
`tools.protos.ExecutionStatistics` protobuf — the same message and encoding that
Bazel's `linux-sandbox` produces, so Bazel's `WindowsSandboxedSpawn` can consume
it via `setResourceUsageFromProto` (feeding `--execution_log`, the JSON profile,
and BEP). The numbers come from the job object, which accounts for the whole
process tree: user/kernel CPU time (`TotalUserTime`/`TotalKernelTime`), peak
memory (`PeakJobMemoryUsed`, reported as KiB to match Linux `ru_maxrss`), and
I/O read/write operation counts. Fields with no Windows analog (e.g. involuntary
context switches) are omitted. The file is the raw serialized message (no length
framing), matching `linux-sandbox`.

### Examples

```powershell
# Run a tool; it can read the whole FS but cannot write anywhere.
BazelSandbox -- mytool.exe --check

# Grant a read-only input and a writable output directory.
BazelSandbox -W C:\work -r C:\work\in.txt -w C:\work\out -- mytool.exe in.txt out\result

# Time out after 60s with a 5s grace period; capture logs.
BazelSandbox -T 60 -t 5 -l out.log -L err.log -- longtool.exe

# Hermetic action: read-only inputs, one writable output, no external network.
BazelSandbox -W C:\work -w C:\work\out -N -- mytool.exe --offline
```

A non-zero exit code is returned when the command exits non-zero (e.g. because a
disallowed access was denied) or when the timeout fires.

## Testing

```powershell
bazel test //...
```

The suite is one unit test plus seven end-to-end categories, each a separate
Bazel test target (`//tests:manifest_unit` and `//tests:enforce_<category>`) so
a failure names the exact area. The enforcement tests are `rules_powershell`
`pwsh_test` targets that carry the launcher/probe binaries as runfiles; the
shared harness resolves their runfiles rlocationpaths (`tests/lib/harness.ps1`).
Tests run serially (`--local_test_jobs=1` in `.bazelrc`): each spawns many real
sandboxed child processes, and running the categories in parallel thrashes
process creation enough to blow the timeouts.

The categories:

* **`manifest_unit`** — framework-free unit tests for the manifest serializer
  (`tests/manifest_builder_test.cpp`). Pins the FNV-1 path hash against golden
  values (a mismatch with the DLL's `NormalizeAndHashPath` is a real bug class),
  and checks the blob header, determinism, and that scopes/flags affect output.
* **`enforce.<category>`** — end-to-end tests that run the real launcher against
  a small `probe` helper (`tests/probe.cpp`, exit code `0` = allowed, `10` =
  denied, `20` = other error). Each category is one script under
  `tests/enforce/`, and they share `tests/lib/harness.ps1` (setup/teardown,
  assertions, per-case named results — no test numbering, zero external
  dependencies, no Pester). The categories:
  * **`scopes`** — the read-only root, blocked working directory, and
    `-r`/`-w`/`-b` scopes (including the `-w` + `-b` override and sibling
    isolation); a **read-only `-r` scope is truly read-only** (it permits reads
    but denies every mutation — write, delete, mkdir, rename); a single-**file**
    `-r` grants exactly that file (not its siblings); a more-specific `-w` child
    overrides a `-r` parent; `-b` makes a path fully inaccessible (it blocks
    **reads** too, not just writes); **multiple disjoint** scopes on one
    invocation each take effect independently (a path in none stays denied);
    **case-insensitive** scope matching; and **child-process propagation** to
    depth 3 (a grandchild is sandboxed too).
  * **`filesystem`** — a broad **intercepted-API** sweep beyond plain read/write:
    `delete`, `mkdir`, `rmdir`, `rename` (including a rename blocked by a `-b`
    destination and a **directory** rename), attribute queries
    (`GetFileAttributes` W and **A**), ANSI `CreateFileA` reads, `CopyFile`,
    handle-based rename (`SetFileInformationByHandle` + `FILE_RENAME_INFO`, the
    path Bazel's own filesystem uses), `CreateHardLink`, and the **alternate
    deletion/mutation mechanisms** the engine hooks separately — handle-based
    delete (`SetFileInformationByHandle` + `FILE_DISPOSITION_INFO`, the path
    .NET's `File.Delete` uses), `FILE_FLAG_DELETE_ON_CLOSE`, and atomic replace
    (`ReplaceFileW`) — each enforced like a write (denied under `-r`, allowed
    under `-w`); plus `GetTempFileName`, the **native** `NtCreateFile` path
    (enforced identically to Win32), and the absent-file distinction (a
    nonexistent read reports *denied* on a read-only scope but *not-found* on a
    writable scope).
  * **`network`** — the `-N`/`-n` network policies (loopback allowed vs.
    external/all blocked) and their propagation to child processes.
  * **`launcher`** — `-l`/`-L` stdout/stderr redirection, exact **exit-code**
    forwarding, `-W` setting the child's working directory, `-T` **timeout**
    termination plus the `-t` **kill-delay** grace period (the force-kill is
    delayed by the grace period, but the launcher returns early if the child
    exits during it), `@response-file` argument expansion, relative scope-path
    resolution, the std-handle repair regression (`tests/stdio_launcher.cpp`
    reproduces Bazel's launch: `STARTF_USESTDHANDLES` with inheritable
    stdout/stderr but **no stdin**, which caused "The handle is invalid"), and
    the **cross-bitness guard** — a non-x64 target is refused up front with exit
    `3` before anything is spawned (so no injection and no hard-error dialog) —
    and the **CLI error contract**: a nonexistent target exe fails the spawn
    (exit `2`), while an empty command after `--` and an unknown flag are usage
    errors (exit `1`), each distinct, non-zero, and never hanging.
  * **`pathforms`** — path-form canonicalization: a file in a denied scope stays
    denied however the path is spelled — forward slashes, `.`/`..` components,
    the `\\?\` prefix, upper case, and an alternate-data-stream (`::$DATA`)
    suffix; the `NUL` device is correctly *not* sandboxed; and a **non-ASCII**
    (UTF-16) path is enforced exactly (allowed when declared, denied otherwise).
  * **`reparse`** — reading through a declared **junction** is allowed while its
    resolved target stays undeclared, and undeclared junctions are denied; the
    same for **file symlinks** and **directory symlinks** (`mklink /D`, a
    distinct reparse tag from a junction), which — like the file-symlink cases —
    are only exercised when the token holds `SeCreateSymbolicLinkPrivilege`
    (skipped otherwise). The engine enforces on the path *as requested*, not the
    resolved target.
  * **`limitations`** — characterization of the **known limitations** below:
    directory enumeration is asserted *un*-enforced; the long-path / 8.3
    short-name behaviors are pinned (short-name results are reported as `NOTE`
    observations because they vary by volume); and **non-ASCII case folding** is
    pinned in both directions (ASCII control, non-ASCII over-deny, and the
    security-relevant non-ASCII `-b` under-deny). It also proves the > `MAX_PATH`
    over-deny is *child-side*: a long-path-aware probe (`probe_lpa`) passes the
    same raw >260 path and is enforced correctly (allow + deny both hold). It also
    pins the **reparse-point escape** (a junction inside a `-w` scope reaching an
    out-of-scope target, which a direct access is denied).

## Known limitations

These are current behaviors of the vendored engine, characterized by the test
suite so a future rewrite that fixes one will make the corresponding test change
loudly. None is an under-deny that would let a *declared* deny be silently
bypassed by a normal long path — they are edge cases:

* **Directory enumeration is not enforced *in the default (non-filtering) mode.***
  `FindFirstFile`/`FindNextFile` on a denied directory succeeds (the entries are
  listed). File *opens* are still enforced; only the listing is visible. Potential
  info-leak surface. **Under `--filter-inputs`** (the `windows-sandbox` default)
  this is closed: undeclared entries are removed from enumeration results at the
  Detours layer, so listings show only declared inputs — matching the symlink
  forest. The limitation therefore applies only to bare permissive-mode runs.
* **Raw paths longer than `MAX_PATH` (260) over-deny.** A non-long-path-aware
  child that passes a raw >260-char path (no `\\?\`) has it truncated by its own
  Win32 layer before the engine sees it, so a legitimate `-r`/`-w` access is
  *over*-denied. The `\\?\` form works correctly (allow and deny both hold).
  This is a child-side issue: setting `longPathAware` on **BazelSandbox.exe**'s
  manifest does **not** fix it (the manifest is per-process and the launcher is
  not the process that opens the file); the child tool must be long-path-aware
  or pass `\\?\` paths. The test suite proves this directly: a long-path-aware
  build of the probe (`probe_lpa`, same source with `longPathAware` in its
  manifest) passes the identical raw >260 path and is enforced correctly — the
  engine supports long paths end to end. The launcher's manifest *does* set
  `longPathAware` for its own file operations (resolving tool/DLL paths,
  `-l`/`-L` outputs). Both the launcher and `probe_lpa` also require the system
  policy `LongPathsEnabled=1` (the `probe_lpa` cases skip if it is off).
* **8.3 short names are not cross-matched.** The engine hashes path fragments in
  long form and does not resolve 8.3 short names (`LONGFI~1.TXT`) to their long
  equivalents, so an exact-path `-b` block can be evaded via the short name. The
  exact manifestation varies by volume (short-name generation may be disabled),
  so these cases are reported as `NOTE` observations rather than asserted.
  BuildXL mitigates this by *disabling* 8.3 generation on its directories (see
  its `ShortNames` DetoursTest); this project does not.
* **Reparse points are not resolved (escape via link into an allowed scope).**
  The manifest sets `IgnoreReparsePoints` + `IgnoreFullReparsePointResolving`, so
  the engine enforces on the path *as requested* and never resolves a
  junction/symlink to its target. A reparse point that lives inside an **allowed**
  scope but points **outside** every scope therefore lets the access reach the
  outside target, even though a direct access to that target is denied. This is
  the class of escape that BuildXL's full reparse-point resolution (its large
  `SymLinkTests` suite — chain-of-symlinks, resolved-path cache, directory-symlink
  selective enforcement) is designed to prevent; those features are intentionally
  disabled here, so the corresponding chain-resolution tests do not apply. The
  suite pins the escape with a deterministic junction case. Note this is the
  *escape* direction (an undeclared target reached through a link inside an
  allowed scope); the *reverse* — a **declared input** reached through the
  execroot's per-entry symlink forest — is resolved and allowed under
  `--filter-inputs` via the `DeclaredInput` marker bit (see
  [`docs/detours-input-filtering.md`](docs/detours-input-filtering.md)), so
  declared inputs stay visible while undeclared ones do not leak.
* **Case-insensitive matching is ASCII-only.** Path fragments are upper-cased
  with `_towupper_l` under the invariant locale, which folds `a`–`z` but not
  non-ASCII letters, so a non-ASCII path is matched **case-sensitively**. NTFS,
  by contrast, is case-insensitive for those characters. This produces an
  over-deny (a differently-cased `-r`/`-w` scope stops matching) and, more
  importantly, an **under-deny**: a `-b` block on `…\CAFÉ` is bypassed by
  accessing `…\café`. Exact-case non-ASCII paths are enforced correctly. This
  behavior is inherited verbatim from BuildXL's Windows engine (it also uses
  `_towupper_l`, never utf8proc, on Windows).
* **Only 64-bit child processes are sandboxed.** This project builds a single
  x64 `DetoursServices.dll`, and the launcher injects it into the child (and the
  manifest carries it in both the x86 and x64 DLL slots). The vendored engine
  *has* the WOW64 machinery to inject a matching-bitness DLL into a differently
  bitted child, but no x86 DLL is provided, so a **32-bit** child cannot load the
  x64 hook DLL. Rather than let that fail late (a blocking hard-error dialog and
  an unenforced child), the launcher **fails closed up front**: it reads the
  target's PE machine type and refuses any non-x64 target with a clear message
  and exit code **3**, before spawning anything (so there is no injection and no
  dialog). Bazel's Windows toolchains are
  64-bit, so this has not mattered in practice; supporting 32-bit tools would
  require also building an x86 `DetoursServices.dll` and pointing the manifest's
  x86 slot at it. (A 32-bit *grandchild* spawned by an x64 tool is a residual
  gap the up-front check cannot see; it is bounded by the same missing x86 DLL.)

## Layout

```
MODULE.bazel              Bazel (bzlmod) deps + pinned Detours http_archive
BUILD.bazel               root Bazel targets: DetoursServices.dll, BazelSandbox, libs
defs.bzl                  shared build constants (Windows target defines)
.bazelrc / .bazelversion  Bazel config (JVM certs, PATH, serial tests) + version
third_party/detours/      BUILD file applied to the fetched upstream Detours
docs/
  vendor-architecture.md  vendored-engine coupling map + policy/manifest subset
  gsoc-proposal-comparison.md  parity vs. GSoC proposal + Bazel CLI contract
  linux-sandbox-comparison.md  flag-by-flag comparison with linux-sandbox
src/
  main.cpp                launcher (options, manifest, Detours injection, waiting)
  manifest_builder.{h,cpp} native FileAccessManifest blob + path hash-tree
  network_detours.{h,cpp} Winsock detours for -N/-n network sandboxing
  detours_compat.h        no-op DetourInit() shim for upstream Detours
  dll_export_anchor.cpp   ensures DetoursServices.dll has an export for injection
tests/
  BUILD.bazel             test targets: manifest_unit, probe(_lpa), pwsh_test's
  manifest_builder_test.cpp unit tests for the manifest serializer + path hash
  probe.cpp               file-op / connect / native / stdio helper for the tests
  probe_lpa.manifest      longPathAware manifest for the long-path-aware probe build
  stdio_launcher.cpp      reproduces Bazel's std-handle setup (regression harness)
  lib/harness.ps1         shared PowerShell harness (setup/teardown, assertions)
  enforce/*.ps1           per-category allow/deny scenarios (one test each)
vendor/
  BUILD.bazel             //vendor:detours_services cc_library (the vendored engine)
  detours-services/       vendored BuildXL DetoursServices engine (+ small hooks
                          for network init and \Device\Afd hardening)
  sandbox-common/         vendored BuildXL shared headers (ReportType.h, ...)
  PROVENANCE.md           upstream commit, file map, and divergence notes
  detours-services.patch  the exact diff vs upstream (applies to a BuildXL checkout)
integration/
  bazel-windows-sandbox.patch  Java-host patch completing Bazel's windows-sandbox
                          runner (targets recent Bazel master); build a bazel-dev.exe with it
  README.md               how to apply the patch, build Bazel, and run the strategy
```

## License

The vendored sources under `vendor/` (Microsoft BuildXL's DetoursServices
engine and shared headers) and the fetched Detours sources retain their original
MIT licenses from Microsoft.

The code original to this repository (`src/`, `tests/`, and the build files —
`MODULE.bazel`, `BUILD.bazel`, and `third_party/`) is not covered by that MIT
license and carries no license grant.
