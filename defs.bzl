"""Shared build constants for the bazel-sandbox-windows targets."""

# Bazel's auto-configured MSVC toolchain pins /D_WIN32_WINNT=0x0601 (Windows 7),
# whereas the Windows SDK would otherwise default to its newest target.
# Re-target Windows 10 (RS5) so the newer file-info classes the vendored engine
# uses (FileDispositionInfoEx / FileRenameInfoEx, NTDDI_WIN10_RS1+) are visible.
# These appear after the toolchain's define on the command line, so they win.
#
# Used by both //:... targets and //vendor:detours_services; keep it here so the
# Windows target version cannot drift between the two packages.
WIN10_DEFINES = [
    "_WIN32_WINNT=0x0A00",
    "NTDDI_VERSION=0x0A000006",
]
