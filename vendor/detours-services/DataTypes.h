// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "stdafx.h"
#include "StringOperations.h"

#include <string>
#include "DebuggingHelpers.h"

// warning C26446: Prefer to use gsl::at() instead of unchecked subscript operator (bounds.4).
// warning C26485: Expression '...': No array to pointer decay (bounds.3).
// warning C26482: Only index into arrays using constant expressions (bounds.2).
// warning C26490: Don't use reinterpret_cast (type.1).
// warning C26497: You can attempt to make 'Check<FAM_FLAG>' constexpr unless it contains any undefined behavior (f.4).
// warning C26812: The enum type 'FileAccessPolicy' is unscoped. Prefer 'enum class' over 'enum' (Enum.3).
#pragma warning( disable : 26446 26485 26482 26490 26497 26812 )

// ----------------------------------------------------------------------------
// ENUMS
// ----------------------------------------------------------------------------

//
// Higher-order macro that enumerates all FileAccessManifestFlag name/value pairs.
// Accepts an arbitrary macro 'm' to which it passes each of the enumerated name/value
// pairs.  This macro should be used to generate the actual enum definition, as well as
// for any other utility methods that should uniformly apply to all enum flags.
//
// IMPORTANT: Keep this in sync with the C# version declared in FileAccessManifest.cs
//
#define FOR_ALL_FAM_FLAGS(m) \
    m(None,                               0x0)            \
    m(BreakOnAccessDenied,                0x1)            \
    m(FailUnexpectedFileAccesses,         0x2)            \
    /* 0x4 (DiagnosticMessagesEnabled) removed: never set.                 */ \
    m(ReportAllFileAccesses,              0x8)            \
    m(ReportAllFileUnexpectedAccesses,    0x10)           \
    m(MonitorNtCreateFile,                0x20)           \
    m(MonitorChildProcesses,              0x40)           \
    /* 0x80 (IgnoreCodeCoverage) removed: never set.                       */ \
    /* 0x100 (ReportProcessArgs) removed: never set.                       */ \
    /* 0x200 (ForceReadOnlyForRequestedReadWrite) removed: never set.      */ \
    m(IgnoreReparsePoints,                0x400)          \
    /* 0x1000 (IgnoreZwRenameFileInformation) and 0x2000                   */ \
    /* (IgnoreSetFileInformationByHandle) removed: never set.              */ \
    /* 0x4000 (UseLargeNtClosePreallocatedList) and 0x8000                 */ \
    /* (UseExtraThreadToDrainNtClose) removed: this launcher never set     */ \
    /* them, so the deferred-NtClose drain subsystem was dead.             */ \
    /* 0x10000 (DisableDetours) removed: never set.                        */ \
    /* 0x20000 (LogProcessData) removed: never set; the private-heap       */ \
    /* memory-stats accounting it gated was dead.                          */ \
    /* 0x40000 (IgnoreGetFinalPathNameByHandle) removed: never set.        */ \
    /* 0x80000 (LogProcessDetouringStatus) removed: never set.             */ \
    /* 0x100000 (HardExitOnErrorInDetours) removed: never set.             */ \
    /* 0x200000 (CheckDetoursMessageCount) removed: never set.             */ \
    /* 0x400000 (IgnoreZwOtherFileInformation) removed: never set.         */ \
    m(MonitorZwCreateOpenQueryFile,       0x800000)       \
    /* 0x1000000 (IgnoreNonCreateFileReparsePoints), 0x2000000             */ \
    /* (IgnoreCreateProcessReport), 0x4000000 (UseLargeEnumerationBuffer), */ \
    /* 0x8000000 (IgnorePreloadedDlls), 0x10000000                         */ \
    /* (DirectoryCreationAccessEnforcement), 0x20000000                    */ \
    /* (ProbeDirectorySymlinkAsDirectory) removed: never set.              */ \
    m(IgnoreFullReparsePointResolving,    0x40000000)

//
// FileAccessManifestFlag enum definition
//
#define GEN_FAM_FLAG_ENUM_NAME_VALUE(name, value) name = value,
enum class FileAccessManifestFlag {
    FOR_ALL_FAM_FLAGS(GEN_FAM_FLAG_ENUM_NAME_VALUE)
};

DEFINE_ENUM_FLAG_OPERATORS(FileAccessManifestFlag)

//
// Checker function for FileAccessManifestFlag enums.
//
// Each generated function looks like:
//
//   inline book CheckDisableDetours(FileAccessManifestFlag flags) { return (flags & FileAccessManifestFlag::DisableDetours) != FileAccessManifestFlag::None; }
//
#define GEN_FAM_FLAG_CHECKER(flag_name, flag_value) \
  inline bool Check##flag_name(FileAccessManifestFlag flags) noexcept { return (flags & FileAccessManifestFlag::flag_name) != FileAccessManifestFlag::None; }
FOR_ALL_FAM_FLAGS(GEN_FAM_FLAG_CHECKER)

inline bool CheckReportAnyAccess(FileAccessManifestFlag flags, bool accessDenied) noexcept
{
    return
        CheckReportAllFileAccesses(flags) ||
        (accessDenied && CheckReportAllFileUnexpectedAccesses(flags));
}

//
// Keep this in sync with the C# version declared in FileAccessManifest.cs
//
#define FOR_ALL_FAM_EXTRA_FLAGS(m) \
    m(NoneExtra,                                         0x0) \
    /* 0x1 (ExplicitlyReportDirectoryProbes), 0x2                          */ \
    /* (PreserveFileSharingBehaviour) removed: never set.                  */ \
    /* 0x4 (EnableLinuxPTraceSandbox), 0x8 (EnableLinuxSandboxLogging),    */ \
    /* 0x10 (AlwaysRemoteInjectDetoursFrom32BitProcess), 0x20              */ \
    /* (UnconditionallyEnableLinuxPTraceSandbox) removed: Linux-only,      */ \
    /* never set by this Windows launcher.                                 */ \
    /* 0x40 (IgnoreDeviceIoControlGetReparsePoint), 0x80                   */ \
    /* (IgnoreUntrackedPathsInFullReparsePointResolving), 0x100            */ \
    /* (MonitorCreateProcessAsUser), 0x200 (SecurityInodeGetattrIsProbe)   */ \
    /* removed: never set.                                                 */ \
    /* Bazel-sandbox fork extensions (not present in BuildXL C#). CODESYNC: */ \
    /* src/manifest_builder.h ExtraFlag_*. */ \
    /* Report a denied READ of an existing-but-undeclared path as NOT_FOUND */ \
    /* instead of ACCESS_DENIED, matching linux-sandbox (undeclared inputs */ \
    /* are absent, not permission-denied). Writes are unaffected. */ \
    m(DeniedReadsAsNotFound,                       0x400) \
    /* Remove undeclared (non-read-allowed) children from directory */ \
    /* enumerations so the process cannot see them. */ \
    m(FilterDirectoryEnumeration,                  0x800) \
    /* Model W write-overlay (experimental, revertable kill-switch). When set, */ \
    /* the directory-enumeration path may INSERT synthetic entries for files */ \
    /* that live only in a process-private write overlay, so a tool sees files */ \
    /* it created even though they were redirected off the real execroot. Off */ \
    /* by default: the shipped subtractive-filter path is byte-for-byte */ \
    /* unchanged. See docs/design/detours-write-overlay-vfs.md. */ \
    m(WriteOverlay,                                0x1000)

enum class FileAccessManifestExtraFlag {
    FOR_ALL_FAM_EXTRA_FLAGS(GEN_FAM_FLAG_ENUM_NAME_VALUE)
};

DEFINE_ENUM_FLAG_OPERATORS(FileAccessManifestExtraFlag)

// Checker function for FileAccessManifestFlagExtra enum.
#define GEN_FAM_EXTRA_FLAG_CHECKER(flag_name, flag_value) \
  inline bool Check##flag_name(FileAccessManifestExtraFlag flags) noexcept { return (flags & FileAccessManifestExtraFlag::flag_name) != FileAccessManifestExtraFlag::NoneExtra; }
FOR_ALL_FAM_EXTRA_FLAGS(GEN_FAM_EXTRA_FLAG_CHECKER)

//
// CODESYNC: Keep this in sync with the C# version declared in Public\Src\Engine\Processes\FileAccessPolicy.cs
//
enum FileAccessPolicy
{
    // Allows a read attempt to succeed if the target file exists.
    FileAccessPolicy_AllowRead = 1,
    // Allows a write attempt to succeed, even if the target file doesn't exist.
    FileAccessPolicy_AllowWrite = 2,
    // Allows a read attempt to succeed if the target file does not exist.
    FileAccessPolicy_AllowReadIfNonExistent = 4,
    // Allows a directory to be created.
    FileAccessPolicy_AllowCreateDirectory = 8,

    // 0x10 (was FileAccessPolicy_ReportAccessIfExistent) removed: per-scope explicit
    // read reporting is never set by this launcher. Reserved gap for layout stability.

    // 0x20 was FileAccessPolicy_ReportUsnAfterOpen (USN reporting/verification,
    // removed in this hard fork). Left as a reserved gap for layout stability.

    // 0x40 (was FileAccessPolicy_ReportAccessIfNonExistent) removed: per-scope explicit
    // read reporting is never set by this launcher. Reserved gap for layout stability.

    // 0x80 (was FileAccessPolicy_ReportDirectoryEnumerationAccess) removed:
    // never set by this launcher. Left as a reserved gap for layout stability.

    // Allows a symlink creation to succeed.
    FileAccessPolicy_AllowSymlinkCreation = 0x100,

    // 0x200 reserved (was FileAccessPolicy_AllowRealInputTimestamps; timestamp virtualization removed post-fork).

    // Override writes allowed by policy based on file existence checks. 
    // Used mainly in the context of shared opaques, where the whole cone under the opaque root is write-allowed by policy (except known inputs).
    // This policy makes sure that writes on undeclared inputs that fall under the write-allowed cone are flagged as DFAs.
    // The way to determine undeclared inputs is based on file existence: if a pip tries to write into a file - allowed by policy - but
    // that was not created by the pip (i.e. the file was there before the first write), then it is a write on an undeclared input
    FileAccessPolicy_OverrideAllowWriteForExistingFiles = 0x400,

    // 0x800 (was FileAccessPolicy_TreatDirectorySymlinkAsDirectory) removed:
    // never set by this launcher. Left as a reserved gap for layout stability.

    // 0x1000 (was FileAccessPolicy_EnableFullReparsePointParsing) removed:
    // never set by this launcher. Left as a reserved gap for layout stability.

    // bazel-sandbox-windows marker (NOT interpreted by BuildXL enforcement): tags a
    // scope that was EXPLICITLY declared as a bazel input/output grant (-r/-w/-d/tool),
    // as opposed to a path merely readable via the blanket whole-filesystem root scope.
    // Set on explicit grant scopes in main.cpp and, because it is <= the 0xFFFF cone
    // inheritance mask (Policy_MaskNothing), it propagates to every descendant of a
    // granted directory. The handle-resolution read fallback (DetouredFunctions.cpp)
    // uses it to rescue symlinks/junctions ONLY when their resolved real target is a
    // declared input - never when the target is just root-baseline readable. This is
    // what stops the bazel execroot symlink (execroot/_main -> the real source tree)
    // from leaking undeclared source files. CODESYNC: Policy_DeclaredInput in
    // src/manifest_builder.h. Enforcement bit-tests (AllowRead(), IndicateUntracked(),
    // etc.) never inspect this bit, so it is inert for access decisions.
    FileAccessPolicy_DeclaredInput = 0x2000,

    // FileAccessPolicy_ReportAccess (the ReportAccessIfExistent|ReportAccessIfNonExistent
    // combo) removed with those bits: per-scope explicit reporting is never set here.

    FileAccessPolicy_AllowAll = FileAccessPolicy_AllowRead | FileAccessPolicy_AllowReadIfNonExistent | FileAccessPolicy_AllowWrite | FileAccessPolicy_AllowCreateDirectory,
};

// Keep this in sync with the C# version declared in FileAccessStatus.cs
enum FileAccessStatus
{
    FileAccessStatus_None = 0,
    FileAccessStatus_Allowed = 1,
    FileAccessStatus_Denied = 2,
    FileAccessStatus_CannotDeterminePolicy = 3
};

// Keep this in sync with the C# version declared in FileAccessManifest.cs
enum FileAccessBucketOffsetFlag
{
    ChainStart = 0x01,
    ChainContinuation = 0x02,
    ChainMask = 0x03
};

// ----------------------------------------------------------------------------
// STRUCTS
// ----------------------------------------------------------------------------

// Generates a uint32_t tag, along with CheckValid() and AssertValid() methods.
//
// In debug builds (when _DEBUG is defined):
//   - Tag value is a sanity check to make sure that we are always looking at a valid record;
//   - CheckValid() checks if the value of the tag is as expected; if it is returns `nullptr`, otherwise returns an error message;
//   - AssertValid() asserts (by calling `assert`) that the tag is valid (i.e., `CheckValid()` returns `nullptr`).
//
// In release builds:
//   - no tag field is generated;
//   - CheckValid() always returns `nullptr`;
//   - AssertValid() is empty.
#ifdef _DEBUG
#define GENERATE_TAG(type_name, tag_value)                          \
    typedef uint32_t TagType;                                       \
    TagType Tag;                                                    \
    inline const char* CheckValid() const noexcept {                \
        return (this->Tag != (uint32_t)tag_value)                   \
             ? "Wrong " #type_name " tag. Expected " #tag_value "." \
             : nullptr;                                             \
    }                                                               \
    inline void AssertValid() const noexcept {                      \
         assert(CheckValid() == nullptr);                           \
    }
#else
#define GENERATE_TAG(type_name, tag_value) \
    inline const char* CheckValid() const noexcept { return nullptr; } \
    inline void AssertValid() const noexcept { }
#endif

// ==========================================================================
// == ManifestDebugFlag
// ==========================================================================
typedef struct ManifestDebugFlag_t
{
    typedef uint32_t    FlagType;
    FlagType            Flag;

    inline const char* CheckValid() const noexcept
    {
#ifdef _DEBUG
        if (this->Flag != 0xDB600001)
        {
            return "The manifest blob is not a Debug-type manifest.";
        }
#else
        if (this->Flag != 0xDB600000)
        {
            return "The manifest blob is not a Release-type manifest.";
        }
#endif
        return nullptr;
    }

    inline bool CheckValidityAndHandleInvalid() const
    {
#ifdef _DEBUG
        // 0xDB600001 => "debug 1 (on)"
        assert(this->Flag == 0xDB600001);
        if (this->Flag != 0xDB600001)
        {
            Dbg(L"The manifest blob is not a Debug-type manifest. ManifestDebugFlag is %x", this->Flag);
            wprintf(L"The manifest blob is not a Debug-type manifest. ManifestDebugFlag is %x", this->Flag);
            // If the manifest debug flag doesn't match, just return false, so we continue without detouring processes.
            // We already logged that there is a mismatch. Also the message is logged to the debug output console.
            // And just in case it is also printed to the console.
            return false;
        }
#else
        // 0xDB600000 => "debug 0 (off)"
        if (this->Flag != 0xDB600000)
        {
            Dbg(L"The manifest blob is not a Release-type manifest. ManifestDebugFlag is %x", this->Flag);
            wprintf(L"The manifest blob is not a Release-type manifest. ManifestDebugFlag is %x", this->Flag);
            // If the manifest debug flag doesn't match, just return false, so we continue without detouring processes.
            // We already logged that there is a mismatch. Also the message is logged to the debug output console.
            // And just in case it is also printed to the console.
            // The old crashing code could lead to a undefined behaviour since it is called from the DLL's attach process handler
            // a crash could lead to many (even infinite) attempts to load the DLL.
            return false;
        }
#endif
        return true;
    }

    /// GetSize
    ///
    /// There are no variable-length members, so the length of this struct can be determined using sizeof.
    size_t GetSize() const noexcept
    {
        return sizeof(ManifestDebugFlag_t);
    }
} ManifestDebugFlag;
typedef const ManifestDebugFlag * PCManifestDebugFlag;

// ==========================================================================
// == ManifestFlags
// ==========================================================================
typedef struct ManifestFlags_t
{
    GENERATE_TAG("ManifestFlags", 0xF1A6B10C);

    typedef uint32_t    FlagsType;
    FlagsType           Flags;

    /// GetSize
    ///
    /// There are no variable-length members, so the length of this struct can be determined using sizeof.
    size_t GetSize() const noexcept
    {
        return sizeof(ManifestFlags_t);
    }
} ManifestFlags;
typedef const ManifestFlags * PCManifestFlags;

// ==========================================================================
// == ManifestExtraFlags
// ==========================================================================
typedef struct ManifestExtraFlags_t
{
    GENERATE_TAG("ManifestExtraFlags", 0xF1A6B10D)

    typedef uint32_t    ExtraFlagsType;
    ExtraFlagsType      ExtraFlags;

    /// GetSize
    ///
    /// There are no variable-length members, so the length of this struct can be determined using sizeof.
    size_t GetSize() const noexcept
    {
        return sizeof(ManifestExtraFlags_t);
    }
} ManifestExtraFlags;
typedef const ManifestExtraFlags * PCManifestExtraFlags;

// ==========================================================================
// == ManifestReport
// ==========================================================================
typedef struct ManifestReport_t
{
    GENERATE_TAG("ManifestReport", 0xFEEDF00D)

    typedef uint32_t    SizeType;
    typedef PathChar    ReportPathType;
    typedef int         ReportHandleType32Bit;
    typedef union ReportType_t
    {
        ReportPathType          ReportPath[ANYSIZE_ARRAY];
        ReportHandleType32Bit   ReportHandle32Bit;
    } ReportType;

    SizeType            Size;
    ReportType          Report;

    /// IsReportHandle
    ///
    /// If the bottom bit of the Size is 1, then the next field is an integer
    /// representing the handle to the report file.
    /// Otherwise, the next field is a path to a report file.
    bool IsReportHandle() const noexcept
    {
        return (Size & 0x1) == 1;
    }

    /// IsReportPresent
    ///
    /// If the size is nonzero then the report is present, otherwise we have an empty report line.
    bool IsReportPresent() const noexcept
    {
        return Size > 0;
    }

    /// GetSize
    ///
    /// Calculate the size of this structure by fields which exist for this struct (excluding the union),
    /// and if the report is present, mask out the lowest bit of the size to find out how large the union was.
    size_t GetSize() const noexcept
    {
        size_t size = 0;

#ifdef _DEBUG
        size += sizeof(TagType);
#endif

        size += sizeof(SizeType);
        size += static_cast<size_t>(Size & ~0x1); // mask out low-order bit to get the actual size of the next field

        return size;
    }
} ManifestReport;
typedef const ManifestReport * PCManifestReport;

// ==========================================================================
// == ManifestDllBlock
// ==========================================================================
typedef struct ManifestDllBlock_t
{
    GENERATE_TAG("ManifestDllBlock", 0xD11B10CC)

    typedef uint32_t    OffsetType;
    typedef CHAR        DllStringType; // $Note(bxl-team): cannot be WCHAR because IMAGE_EXPORT_DIRECTORY used by detours only supports ASCII
    typedef const DllStringType *PCDllStringType;

    OffsetType          StringBlockSize;
    OffsetType          StringCount;
    OffsetType          DllOffsets[ANYSIZE_ARRAY];
    //The strings follow the table of offsets
    //DllStringType       StringBlock[ANYSIZE_ARRAY];

    /// GetDllString
    ///
    /// Calculate the location of the dll string at index and return that string.
    PCDllStringType GetDllString(size_t index) const noexcept
    {
        assert(index < StringCount);
        PCDllStringType stringBlock = reinterpret_cast<PCDllStringType>(DllOffsets + StringCount);
        assert(stringBlock != nullptr);
        return &stringBlock[DllOffsets[index]];
    }

#pragma warning( push )
// warning C26451: Arithmetic overflow: Using operator '+' on a 4 byte value and then casting the result to a 8 byte value. Cast the value to the wider type before calling operator '+' to avoid overflow (io.2).
#pragma warning( disable : 26451)
    /// GetSize
    ///
    /// Calculate the size of this structure by fields which exist for this struct, and the total
    /// size of the StringBlock (in StringBlockSize).
    size_t GetSize() const noexcept
    {
        size_t size = 0;

#ifdef _DEBUG
        size += sizeof(TagType);
#endif
        // Two count values + variable number of offsets
        size += sizeof(OffsetType) * (2U + StringCount);
        size += StringBlockSize;

        return size;
    }
#pragma warning( pop )
} ManifestDllBlock;
typedef const ManifestDllBlock * PCManifestDllBlock;

// ==========================================================================
// == ManifestRecord
// ==========================================================================
typedef struct ManifestRecord_t
{
    typedef const ManifestRecord_t * PCManifestRecord; // typedef in inner scope for expressive power

    GENERATE_TAG("ManifestRecord", 0xF00DCAFE)

    typedef uint32_t    HashType;
    typedef uint32_t    PolicyType;
    typedef uint32_t    PathIdType;
    typedef uint32_t    BucketCountType;
    typedef uint32_t    ChildOffsetType;
    typedef PCPathChar  PartialPathType;

    HashType            Hash;
    PolicyType          ConePolicy;
    PolicyType          NodePolicy;
    PathIdType          PathId;
    BucketCountType     BucketCount;
    ChildOffsetType     Buckets[ANYSIZE_ARRAY];
    // PartialPathType PartialPath (after the end of the Buckets array)

#pragma warning( push )
// warning C26472: Don't use a static_cast for arithmetic conversions. Use brace initialization, gsl::narrow_cast or gsl::narrow (type.1).
#pragma warning( disable : 26472)
    inline DWORD GetPathId() const noexcept {
        return static_cast<DWORD>(this->PathId);
    }

    inline FileAccessPolicy GetConePolicy() const noexcept {
        return static_cast<FileAccessPolicy>(this->ConePolicy);
    }

    // If a specific policy was set for this node, leaving its underlying scope explicitly out, that one is returned. Otherwise, the regular scope
    // policy also applies for this node
    inline FileAccessPolicy GetNodePolicy() const noexcept {
        return static_cast<FileAccessPolicy>(this->NodePolicy);
    }
#pragma warning( pop )

    PCManifestRecord GetChildRecord(BucketCountType index) const noexcept
    {
        assert(index < this->BucketCount);

        const ChildOffsetType childOffset = this->Buckets[index];
        if (childOffset == 0)
        {
            return nullptr;
        }

        PCManifestRecord childRecord = reinterpret_cast<PCManifestRecord>(reinterpret_cast<const BYTE *>(this) + (childOffset & ~FileAccessBucketOffsetFlag::ChainMask));
        assert(childRecord != nullptr);
        childRecord->AssertValid();

        return childRecord;
    }

    bool IsCollisionChainStart(BucketCountType index) const noexcept
    {
        assert(index < this->BucketCount);

        const ChildOffsetType childOffset = this->Buckets[index];
        return (childOffset & FileAccessBucketOffsetFlag::ChainStart) != 0;
    }

    bool IsCollisionChainContinuation(BucketCountType index) const noexcept
    {
        assert(index < this->BucketCount);

        const ChildOffsetType childOffset = this->Buckets[index];
        return (childOffset & FileAccessBucketOffsetFlag::ChainContinuation) != 0;
    }

    PartialPathType GetPartialPath() const noexcept
    {
        const BucketCountType numBuckets = this->BucketCount;
        const PartialPathType path = reinterpret_cast<PartialPathType>(&(this->Buckets[numBuckets]));

        return path;
    }

    __success(return)
    bool FindChild(
        __in  PCPathChar target,
        __in  size_t targetLength,
        __out PCManifestRecord& child) const;
} ManifestRecord;
typedef const ManifestRecord * PCManifestRecord; // duplicated for use in scopes outside of the struct
