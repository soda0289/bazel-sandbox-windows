// DetourUpdateProcessWithDll (used to inject this DLL) requires the target DLL
// to export at least one function (it wires an import to ordinal #1). The
// vendored DetoursServices exports are C++-decorated; this provides a single
// stable, undecorated export so the DLL always has a valid export table.
extern "C" __declspec(dllexport) void BazelSandboxDetoursServicesAnchor() {}
