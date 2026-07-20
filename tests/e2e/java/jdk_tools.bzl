"""Re-exports an individual executable (java / javac) from the resolved hermetic
Java runtime toolchain so a cc_test can hand its runfiles path to a test via
`$(rlocationpath)`.

The remote JDK pinned in .bazelrc (`--java_runtime_version=remotejdk_21`) is a
full JDK, so its JavaRuntimeInfo.files depset carries bin/javac.exe alongside
bin/java.exe. This rule picks the one named by `tool` as its single default
output (kept at its real runfiles path so the adjacent JDK DLLs resolve) and
carries the WHOLE JDK tree as runfiles.
"""

def _jdk_tool_impl(ctx):
    jrt = ctx.toolchains["@bazel_tools//tools/jdk:runtime_toolchain_type"].java_runtime
    want = "/bin/" + ctx.attr.tool + ".exe"
    files = jrt.files.to_list()
    target = None
    for f in files:
        if f.path.replace("\\", "/").endswith(want):
            target = f
            break
    if target == None:
        fail("could not find %s in the resolved java runtime" % want)
    return [DefaultInfo(
        files = depset([target]),
        runfiles = ctx.runfiles(files = files),
    )]

jdk_tool = rule(
    implementation = _jdk_tool_impl,
    attrs = {"tool": attr.string(mandatory = True, doc = "bin/<tool>.exe to re-export (java or javac)")},
    toolchains = ["@bazel_tools//tools/jdk:runtime_toolchain_type"],
)
