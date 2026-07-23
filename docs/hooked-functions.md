# Hooked Windows API functions

This is the authoritative list of every Windows API the sandbox intercepts
(detours) at runtime, grouped by owning module. The single source of truth is the
`ATTACH(...)` table in
[`vendor/detours-services/DetoursServices.cpp`](../vendor/detours-services/DetoursServices.cpp)
(`AttachDetours()`); this document mirrors it. If you add or remove a hook, update
both.

Each entry is attached with Microsoft Detours: `Real_<Name> = ::<Name>` captures
the original trampoline, and `DetourAttach()` redirects the function body to
`Detoured_<Name>` (implemented in
[`vendor/detours-services/DetouredFunctions.cpp`](../vendor/detours-services/DetouredFunctions.cpp)).

## Totals

| Module | Hooked functions |
| --- | ---: |
| `kernel32.dll` (Win32 file/process API) | 62 |
| `ntdll.dll` (native syscall layer) | 11 |
| `advapi32.dll` (EFS encryption API) | 6 |
| **Total** | **79** |

Notes on the count:

* 77 functions are hooked unconditionally via the `ATTACH()` macro; 2 more
  (`GetFileInformationByName`, `CopyFile2`) are resolved dynamically with
  `GetProcAddress` and hooked only when present (they are Win8+/Win11 APIs and may
  be absent on older OSes / missing from the import lib). Both are counted under
  `kernel32.dll` above; at runtime they are resolved preferring `kernelbase.dll`
  and falling back to `kernel32.dll`.
* "Owning module" is the DLL that exports the symbol we bind to (`::<Name>`).
  Many `kernel32.dll` entry points are thin forwarders to `kernelbase.dll`, but we
  attach to the `kernel32.dll` surface, so that is what is listed.
* **WinDbg exception:** only the four `CreateProcess*` hooks are installed when the
  host process is WinDbg (`GetProcessKind() == WinDbg`); all file hooks below are
  skipped in that case so the debugger is not disturbed. Child processes are still
  detoured.

The ANSI (`*A`) variants that take a path input generally widen their arguments and
delegate to the corresponding wide (`*W`) hook, inheriting all policy / overlay /
filter behavior; ANSI variants that *return* a path in an out-buffer delegate to
the wide hook and convert the result back with `WideCharToMultiByte`. See
[`design/detours-input-filtering.md`](design/detours-input-filtering.md) and
[`design/detours-write-overlay-vfs.md`](design/detours-write-overlay-vfs.md) for
the policy, `--filter-inputs`, and `--write-overlay` mechanics referenced below.

---

## `ntdll.dll` — native syscall layer (11)

These sit *beneath* the Win32 wrappers and are the real enforcement backstop:
direct-syscall callers, the CRT, and internal `kernelbase` paths all funnel here.

| Function | Role in the sandbox |
| --- | --- |
| `NtCreateFile` | Native create/open backstop: read/write policy enforcement + `--write-overlay` redirect for opens that bypass `CreateFileW`. |
| `NtOpenFile` | As `NtCreateFile` for the open-only native path. |
| `ZwCreateFile` | `Zw` alias of `NtCreateFile` (same behavior; different export used from kernel-mode-style callers). |
| `ZwOpenFile` | `Zw` alias of `NtOpenFile`. |
| `NtQueryAttributesFile` | Handle-less native attribute probe: masks undeclared inputs as `NOT_FOUND` under `--filter-inputs`. |
| `NtQueryFullAttributesFile` | As above, full-attribute variant. |
| `NtQueryDirectoryFile` | Directory enumeration backstop: applies the enumeration input filter (`ApplyEnumerationFilterNt`) and the write-overlay splice (`InsertOverlayEntries`). This is where **all** `FindFirst/FindNext` enumeration is actually virtualized. |
| `NtQueryDirectoryFileEx` | Modern enumeration successor; same filter + overlay-splice logic. |
| `ZwQueryDirectoryFile` | `Zw` alias of `NtQueryDirectoryFile`. |
| `NtClose` | Handle-tracking teardown: keeps the handle→overlay map consistent when tracked handles close (see the `Detoured_NtClose` comment in the source). |
| `ZwSetInformationFile` | Rename / delete-on-close (`FILE_RENAME_INFORMATION`, `FILE_DISPOSITION`): enforces write policy and applies the overlay redirect to the rename target. |

---

## `kernel32.dll` — Win32 file & process API (62)

### Process creation (4)

| Function | Role |
| --- | --- |
| `CreateProcessW` | Injects the DetoursServices DLL into the child (propagating the sandbox), enforces policy on the image path, and applies the overlay working-directory redirect. **Always hooked** (even under WinDbg). |
| `CreateProcessA` | Widens + delegates to the wide path. |
| `CreateProcessAsUserW` | As `CreateProcessW` for the token-launch variant. |
| `CreateProcessAsUserA` | Widens + delegates. |

### File open / create (2)

| Function | Role |
| --- | --- |
| `CreateFileW` | Core read/write policy enforcement + `--write-overlay` redirect for Win32 opens. |
| `CreateFileA` | Widens + delegates to `CreateFileW`. |

### Attribute & information probes (9)

| Function | Role |
| --- | --- |
| `GetFileAttributesW` | Read/probe policy; masks undeclared inputs under `--filter-inputs`. |
| `GetFileAttributesA` | Widens + delegates. |
| `GetFileAttributesExW` | As above, extended info. |
| `GetFileAttributesExA` | Widens + delegates. |
| `GetFileInformationByName` | *Dynamically resolved* (Win11 handle-less stat used by libuv's fast path); hooked so it is filtered like the other read paths. Absent → libuv falls back to the hooked `CreateFileW`. |
| `GetFileInformationByHandle` | Handle-based info query. |
| `GetFileInformationByHandleEx` | Handle-based extended info query. |
| `SetFileInformationByHandle` | Handle-based set (rename/disposition) — write-policy relevant. |
| `GetVolumePathNameW` | Volume mount-point resolution (read-only query passed through under the sandbox). |

### Current directory (2)

| Function | Role |
| --- | --- |
| `GetCurrentDirectoryW` | Reverse-maps an overlay backing-store cwd back to the virtual execroot so an overlay-only working directory is not leaked. |
| `GetCurrentDirectoryA` | Delegates to the wide hook, then narrows to ANSI (the PEB read has no `Nt*` backstop, so the A variant needs its own hook). |

### Copy / move / replace / delete (23)

| Function | Role |
| --- | --- |
| `CopyFileW` | Source read + destination write policy; overlay redirect of the destination. |
| `CopyFileA` | Widens + delegates. |
| `CopyFileExW` / `CopyFileExA` | Extended copy; same policy. |
| `CopyFileTransactedW` / `CopyFileTransactedA` | Transacted copy; same policy. |
| `CopyFile2` | *Dynamically resolved* (Win8+); self-contained kernel copy **not** backstopped by `NtCreateFile`, so hooked explicitly to apply the overlay redirect. |
| `MoveFileW` / `MoveFileA` | Rename/move; source + destination policy, destination overlay redirect. |
| `MoveFileExW` / `MoveFileExA` | Extended move (the ANSI form routes via `MoveFileWithProgressW`). |
| `MoveFileWithProgressW` / `MoveFileWithProgressA` | Move with progress callback; same policy. |
| `MoveFileTransactedW` / `MoveFileTransactedA` | Transacted move; same policy. |
| `ReplaceFileW` / `ReplaceFileA` | Replace-file (atomic swap + backup); multi-path policy. |
| `DeleteFileW` / `DeleteFileA` | Delete; write policy. |

### Hard links & symbolic links (4)

| Function | Role |
| --- | --- |
| `CreateHardLinkW` / `CreateHardLinkA` | Link creation; source + destination policy. |
| `CreateSymbolicLinkW` / `CreateSymbolicLinkA` | Symlink creation; destination write policy + reparse handling. |

### Directory enumeration (7)

| Function | Role |
| --- | --- |
| `FindFirstFileExW` | Opens the search directory, **registers the search-handle overlay** (the key that lets the `NtQueryDirectoryFile` hook filter/splice), performs the access check, and applies the write-overlay splice. |
| `FindFirstFileW` | Thin wrapper → `FindFirstFileExW`. |
| `FindFirstFileExA` | Widens + delegates to `FindFirstFileExW`, converts `WIN32_FIND_DATAW`→`A`. |
| `FindFirstFileA` | Routes through `FindFirstFileExA`. |
| `FindNextFileW` | Applies the enumeration input filter and appends the write-overlay tail entries. |
| `FindNextFileA` | Delegates to `FindNextFileW`, converts the record to ANSI. |
| `FindClose` | Releases per-search-handle overlay/enumeration state. |

### Directory create / remove (6)

| Function | Role |
| --- | --- |
| `CreateDirectoryW` / `CreateDirectoryA` | Create; write policy + overlay redirect + parent-splice. |
| `CreateDirectoryExW` / `CreateDirectoryExA` | Create-with-template; same. |
| `RemoveDirectoryW` / `RemoveDirectoryA` | Remove; write policy. |

### Temp files, mappings & misc (7)

| Function | Role |
| --- | --- |
| `GetTempFileNameW` | Creates a uniquely-named temp file → subject to write policy. |
| `GetTempFileNameA` | Widens + delegates. |
| `OpenFileMappingW` / `OpenFileMappingA` | Named section open; access reporting. |
| `OpenFileById` | Open-by-file-ID; policy on the resolved path. |
| `CreatePipe` | Anonymous pipe creation (tracked for std-handle plumbing). |
| `GetFinalPathNameByHandleW` | Reverse-maps a resolved handle path from the overlay backing store back to the virtual execroot. |
| `GetFinalPathNameByHandleA` | Delegates to the wide hook (gated on `--write-overlay`), converts to ANSI. |
| `DeviceIoControl` | Hooked passthrough (kept attached for reparse/volume IOCTL coverage). |

---

## `advapi32.dll` — EFS encryption API (6)

| Function | Role |
| --- | --- |
| `EncryptFileW` / `EncryptFileA` | EFS encrypt-in-place; write policy. |
| `DecryptFileW` / `DecryptFileA` | EFS decrypt-in-place; write policy. |
| `OpenEncryptedFileRawW` / `OpenEncryptedFileRawA` | Raw encrypted-file backup/restore open; policy on the target. |

---

## Verifying this list

To regenerate the raw hook list from source:

```powershell
Select-String -Path vendor\detours-services\DetoursServices.cpp `
  -Pattern '^\s*ATTACH\((\w+)\);' |
  ForEach-Object { $_.Matches[0].Groups[1].Value }
```

Add the two dynamically-resolved hooks (`GetFileInformationByName`, `CopyFile2`),
which are attached via explicit `GetProcAddress` + `DetourAttach` blocks rather than
the `ATTACH()` macro.
