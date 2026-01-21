load("@prelude//cxx:cxx_toolchain_types.bzl", "LinkerType")
load("@prelude//toolchains:cxx.bzl", "CxxToolsInfo")

def _clang_tools_impl(_ctx) -> list[Provider]:
    return [
        DefaultInfo(),
        CxxToolsInfo(
            compiler = "clang",
            compiler_type = "clang",
            cxx_compiler = "clang++",
            asm_compiler = "clang",
            asm_compiler_type = "clang",
            rc_compiler = None,
            cvtres_compiler = None,
            archiver = "llvm-ar",
            archiver_type = "gnu",
            linker = "clang++",
            linker_type = LinkerType("gnu"),
        ),
    ]

clang_tools = rule(
    impl = _clang_tools_impl,
    attrs = {},
)
