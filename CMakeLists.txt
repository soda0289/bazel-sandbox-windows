cmake_minimum_required(VERSION 3.24)
project(bazel-sandbox-windows CXX)

# ---------------------------------------------------------------------------
# This project builds a standalone Windows process sandbox that reproduces
# BuildXL's BazelSandbox using ONLY:
#   * upstream microsoft/Detours (fetched from GitHub, built as a static lib)
#   * the vendored microsoft/BuildXL "DetoursServices" enforcement engine
#     (vendor/detours-services), built into the injected hook DLL.
#
# Two binaries are produced:
#   * DetoursServices.dll  - the hook DLL injected into every sandboxed child.
#   * BazelSandbox.exe      - the launcher; builds the file-access manifest and
#                             injects the DLL into a suspended child using
#                             upstream Detours directly (no BuildXL code linked).
# ---------------------------------------------------------------------------

if(NOT WIN32)
    message(FATAL_ERROR "bazel-sandbox-windows only builds on Windows (MSVC).")
endif()
if(NOT MSVC)
    message(FATAL_ERROR "An MSVC toolchain is required.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CRITICAL: force the *static release* CRT (/MT) for every configuration.
#   * DetoursServices.cpp #errors out unless linked with a static native runtime
#     (a DLL CRT would get loaded into every detoured process, which is unsafe).
#   * Static *release* (/MT, not /MTd) means `_DEBUG` is never defined, which is
#     required for the manifest blob format: the debug "tag" words and the
#     0xDB600001 debug marker are only present when `_DEBUG` is set, and our
#     native manifest builder (src/manifest_builder.cpp) always emits the
#     release, tag-less form (DebugFlag == 0xDB600000). Builder and DLL parser
#     MUST agree, so pin static release.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# Put every binary in the same directory so the exe finds both DLLs at runtime.
foreach(cfg "" _DEBUG _RELEASE _RELWITHDEBINFO _MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY${cfg} "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY${cfg} "${CMAKE_BINARY_DIR}/bin")
endforeach()

# ---------------------------------------------------------------------------
# Upstream Detours (latest from GitHub, or a local checkout via -DDETOURS_SOURCE_DIR).
# ---------------------------------------------------------------------------
set(DETOURS_SOURCE_DIR "" CACHE PATH
    "Optional local microsoft/Detours checkout. If empty, it is fetched from GitHub.")

if(DETOURS_SOURCE_DIR STREQUAL "")
    include(FetchContent)
    FetchContent_Declare(
        detours
        GIT_REPOSITORY https://github.com/microsoft/Detours.git
        GIT_TAG        main
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(detours)
    set(DETOURS_SOURCE_DIR "${detours_SOURCE_DIR}")
endif()

set(DETOURS_SRC_DIR "${DETOURS_SOURCE_DIR}/src")
if(NOT EXISTS "${DETOURS_SRC_DIR}/detours.cpp")
    message(FATAL_ERROR "Detours sources not found at ${DETOURS_SRC_DIR}")
endif()

# disasm.cpp #includes the per-architecture disassemblers, and creatwth.cpp
# #includes uimports.cpp, so only these translation units are compiled directly.
add_library(detours STATIC
    "${DETOURS_SRC_DIR}/detours.cpp"
    "${DETOURS_SRC_DIR}/modules.cpp"
    "${DETOURS_SRC_DIR}/disasm.cpp"
    "${DETOURS_SRC_DIR}/image.cpp"
    "${DETOURS_SRC_DIR}/creatwth.cpp"
)
target_include_directories(detours PUBLIC "${DETOURS_SRC_DIR}")
# Detours' own headers warn/erroring cleanly under /W4 is not our concern here.
target_compile_options(detours PRIVATE /W0 /wd4100)

# ---------------------------------------------------------------------------
# Vendored BuildXL DetoursServices engine.
# ---------------------------------------------------------------------------
set(VENDOR "${CMAKE_SOURCE_DIR}/vendor/detours-services")
# BuildXL.Sandbox.Common headers (ReportType.h etc.) used by the engine.
set(VENDOR_COMMON "${CMAKE_SOURCE_DIR}/vendor/sandbox-common")

# Sources shared/used by the injected hook DLL (DetoursServices.dll). Matches
# the `detoursDll` source set in DetoursServices.dsc.
set(DETOURS_DLL_SOURCES
    "${VENDOR}/Assertions.cpp"
    "${VENDOR}/CanonicalizedPath.cpp"
    "${VENDOR}/PolicyResult.cpp"
    "${VENDOR}/PolicyResult_common.cpp"
    "${VENDOR}/DebuggingHelpers.cpp"
    "${VENDOR}/DetoursServices.cpp"
    "${VENDOR}/DetouredFunctions.cpp"
    "${VENDOR}/DetoursHelpers.cpp"
    "${VENDOR}/FileAccessHelpers.cpp"
    "${VENDOR}/DetouredScope.cpp"
    "${VENDOR}/StringOperations.cpp"
    "${VENDOR}/SendReport.cpp"
    "${VENDOR}/stdafx.cpp"
    "${VENDOR}/MetadataOverrides.cpp"
    "${VENDOR}/HandleOverlay.cpp"
    "${VENDOR}/PolicySearch.cpp"
    "${VENDOR}/DeviceMap.cpp"
    "${VENDOR}/DetouredProcessInjector.cpp"
    "${VENDOR}/SubstituteProcessExecution.cpp"
    "${VENDOR}/FilesCheckedForAccess.cpp"
    "${VENDOR}/PathTree.cpp"
    "${VENDOR}/TreeNode.cpp"
)

# Windows import libraries the vendored engine needs.
set(WIN_LIBS advapi32 ole32 oleaut32 pathcch shlwapi user32 shell32 ntdll rpcrt4)

# Silence the mountain of warnings from the vendored MSVC-specific code, and
# force-include stdafx.h so every vendored TU pulls in <windows.h> + <detours.h>
# first (this is what BuildXL's precompiled header does; some TUs such as
# FilesCheckedForAccess.cpp otherwise never include windows.h and fail on
# LPCBYTE / the COM `interface` macro).
set(VENDOR_COMPILE_OPTIONS /W0 /wd4100 /wd4996 /EHsc /bigobj /FIstdafx.h)
# NOTE: do NOT define WIN32_LEAN_AND_MEAN here - the vendored DetoursServices.h
# uses the COM `interface` macro, which windows.h only defines in the full
# (non-lean) configuration.
set(VENDOR_COMPILE_DEFS _CRT_SECURE_NO_WARNINGS UNICODE _UNICODE NOMINMAX)

# ---------------------------------------------------------------------------
# BazelSandbox network sandboxing (-N / -n) Winsock detours.
#
# Compiled as a SEPARATE static library (not part of the vendored source set)
# because it must include <winsock2.h> BEFORE <windows.h>. The vendored engine
# force-includes stdafx.h (which pulls <windows.h> first), so the Winsock code
# cannot live in a TU that uses that force-include. Its public header
# (src/network_detours.h) is Winsock-free, so the engine TUs can call into it.
# ---------------------------------------------------------------------------
add_library(network_detours STATIC "${CMAKE_SOURCE_DIR}/src/network_detours.cpp")
target_compile_definitions(network_detours PRIVATE
    UNICODE _UNICODE NOMINMAX _CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
target_include_directories(network_detours PRIVATE "${CMAKE_SOURCE_DIR}/src")
# `detours` provides <detours.h>; ws2_32 provides the Winsock APIs we detour.
target_link_libraries(network_detours PRIVATE detours ws2_32)

# ---------------------------------------------------------------------------
# DetoursServices.dll - the hook DLL injected into every sandboxed child.
# ---------------------------------------------------------------------------
add_library(DetoursServices SHARED
    ${DETOURS_DLL_SOURCES}
    "${CMAKE_SOURCE_DIR}/src/dll_export_anchor.cpp"
)
target_compile_definitions(DetoursServices PRIVATE
    DETOURS_SERVICES_NATIVES_LIBRARY ${VENDOR_COMPILE_DEFS})
# Force-include the DetourInit() compatibility shim (see src/detours_compat.h)
# so the vendored engine links against stock upstream Detours.
target_compile_options(DetoursServices PRIVATE ${VENDOR_COMPILE_OPTIONS} /FIdetours_compat.h)
target_include_directories(DetoursServices PRIVATE "${VENDOR}" "${VENDOR_COMMON}" "${CMAKE_SOURCE_DIR}/src")
# network_detours implements the Winsock hooks; ws2_32 must be imported directly
# by the DLL so those APIs are present in every sandboxed process at attach time.
target_link_libraries(DetoursServices PRIVATE detours network_detours ws2_32 ${WIN_LIBS})
set_target_properties(DetoursServices PROPERTIES OUTPUT_NAME "DetoursServices")

# ---------------------------------------------------------------------------
# BazelSandbox.exe - the launcher.
#
# It builds the file-access manifest itself (src/manifest_builder.cpp, which
# reimplements BuildXL's FileAccessManifest serializer and path hash) and injects
# DetoursServices.dll into the child using upstream Detours directly
# (DetourCreateProcessWithDllEx + DetourCopyPayloadToProcess). It links ONLY
# against Detours - no BuildXL code is compiled into or loaded by the launcher.
# ---------------------------------------------------------------------------
add_executable(BazelSandbox
    "${CMAKE_SOURCE_DIR}/src/main.cpp"
    "${CMAKE_SOURCE_DIR}/src/manifest_builder.cpp"
    # Embedded application manifest (asInvoker + longPathAware for the
    # launcher's own file operations). MSVC links .manifest sources directly.
    "${CMAKE_SOURCE_DIR}/src/BazelSandbox.manifest"
)
target_compile_definitions(BazelSandbox PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(BazelSandbox PRIVATE "${CMAKE_SOURCE_DIR}/src")
# Linking `detours` also brings in its public include directory for <detours.h>.
target_link_libraries(BazelSandbox PRIVATE detours)
set_target_properties(BazelSandbox PROPERTIES OUTPUT_NAME "BazelSandbox")

# Ensure the injected hook DLL is built and sits next to the exe.
add_dependencies(BazelSandbox DetoursServices)

# ---------------------------------------------------------------------------
# Tests (enabled by default; disable with -DBAZEL_SANDBOX_BUILD_TESTS=OFF).
#   * manifest_unit  - framework-free unit tests for the manifest serializer.
#   * enforce.<name> - end-to-end tests that run the real launcher + probe and
#                      assert the sandbox allows/denies operations as configured.
#                      One CTest test per category under tests/enforce/.
# Run with:  ctest --test-dir build -C Release --output-on-failure
# ---------------------------------------------------------------------------
option(BAZEL_SANDBOX_BUILD_TESTS "Build and register the test suite" ON)
if(BAZEL_SANDBOX_BUILD_TESTS)
    enable_testing()

    # Unit test: links the serializer sources directly (no BuildXL/Detours).
    add_executable(manifest_builder_test
        "${CMAKE_SOURCE_DIR}/tests/manifest_builder_test.cpp"
        "${CMAKE_SOURCE_DIR}/src/manifest_builder.cpp"
    )
    target_compile_definitions(manifest_builder_test PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_include_directories(manifest_builder_test PRIVATE "${CMAKE_SOURCE_DIR}/src")
    add_test(NAME manifest_unit COMMAND manifest_builder_test)

    # probe helper used by the enforcement tests (a plain, un-sandboxed tool).
    add_executable(probe "${CMAKE_SOURCE_DIR}/tests/probe.cpp")
    target_compile_definitions(probe PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

    # A long-path-aware build of the same probe source. Used only by the
    # long-path test to show a raw >MAX_PATH access (no \\?\) is enforced
    # correctly when the child tool is long-path aware (see tests/enforce).
    add_executable(probe_lpa
        "${CMAKE_SOURCE_DIR}/tests/probe.cpp"
        "${CMAKE_SOURCE_DIR}/tests/probe_lpa.manifest")
    target_compile_definitions(probe_lpa PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

    # Harness that reproduces Bazel's std-handle launch and runs
    # "BazelSandbox -- probe stdio".
    add_executable(stdio_launcher "${CMAKE_SOURCE_DIR}/tests/stdio_launcher.cpp")
    target_compile_definitions(stdio_launcher PRIVATE
        UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

    # Integration tests: one PowerShell script per category under tests/enforce/,
    # each dot-sourcing tests/lib/harness.ps1. Registered as enforce.<category>.
    set(BAZEL_SANDBOX_ENFORCE_CATEGORIES
        scopes filesystem network launcher pathforms reparse limitations)
    foreach(cat IN LISTS BAZEL_SANDBOX_ENFORCE_CATEGORIES)
        add_test(NAME "enforce.${cat}" COMMAND powershell.exe
            -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_SOURCE_DIR}/tests/enforce/${cat}.ps1"
            -Sandbox "$<TARGET_FILE:BazelSandbox>"
            -Probe "$<TARGET_FILE:probe>"
            -StdioLauncher "$<TARGET_FILE:stdio_launcher>"
            -TempDir "${CMAKE_BINARY_DIR}/testtmp/${cat}")
        set_tests_properties("enforce.${cat}" PROPERTIES
            REQUIRED_FILES "$<TARGET_FILE:BazelSandbox>;$<TARGET_FILE:probe>;$<TARGET_FILE:stdio_launcher>")
    endforeach()
endif()
