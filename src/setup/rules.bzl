def _ipsw_download_impl(ctx):
    out = ctx.actions.declare_output(ctx.attrs.output_name or "firmware.ipsw")
    
    cmd = [
        ctx.attrs.ipsw_tool[RunInfo],
        "download",
        "--device",
        ctx.attrs.device,
        "--build",
        ctx.attrs.build,
        "--output",
        out.as_output(),
    ]

    ctx.actions.run(cmd, category = "ipsw_download")
    return [DefaultInfo(default_output = out)]

ipsw_download = rule(
    impl = _ipsw_download_impl,
    attrs = {
        "device": attrs.string(),
        "build": attrs.string(),
        "output_name": attrs.option(attrs.string(), default = None),
        "ipsw_tool": attrs.exec_dep(default = "//src/tools/ipsw:ipsw"),
    },
)

def _ipsw_extract_impl(ctx):
    out = ctx.actions.declare_output(ctx.attrs.output_dir_name or "extracted")
    
    cmd = [
        ctx.attrs.ipsw_tool[RunInfo],
        "extract",
        "--input",
        ctx.attrs.ipsw,
        "--output",
        out.as_output(),
    ]

    ctx.actions.run(cmd, category = "ipsw_extract")
    return [DefaultInfo(default_output = out)]

ipsw_extract = rule(
    impl = _ipsw_extract_impl,
    attrs = {
        "ipsw": attrs.source(),
        "output_dir_name": attrs.option(attrs.string(), default = None),
        "ipsw_tool": attrs.exec_dep(default = "//src/tools/ipsw:ipsw"),
    },
)

def _ipsw_decrypt_impl(ctx):
    out = ctx.actions.declare_output(ctx.attrs.output_name or "rootfs.dmg")
    
    # We need to find the DMG file within the extracted directory.
    # Since we can't easily do globbing on a directory artifact in Starlark without a custom action/script,
    # we will wrap the logic in a shell command.
    
    script = ctx.actions.declare_output("decrypt_script.sh")
    
    # Generate a script to find the DMG and run decrypt
    script_content = """#!/bin/bash
set -e
EXTRACTED_DIR="$1"
OUTPUT="$2"
KEY="$3"
IPSW_TOOL="$4"

# Find the largest DMG
DMG=$(find "$EXTRACTED_DIR" -name "*.dmg" -print0 | xargs -0 ls -S | head -n 1)

if [ -z "$DMG" ]; then
    echo "No DMG found in $EXTRACTED_DIR"
    exit 1
fi

"$IPSW_TOOL" decrypt --input "$DMG" --output "$OUTPUT" --key "$KEY"
"""
    ctx.actions.write(script, script_content, is_executable = True)

    cmd = [
        script,
        ctx.attrs.extracted_dir,
        out.as_output(),
        ctx.attrs.key,
        ctx.attrs.ipsw_tool[RunInfo],
    ]

    ctx.actions.run(cmd, category = "ipsw_decrypt")
    return [DefaultInfo(default_output = out)]

ipsw_decrypt = rule(
    impl = _ipsw_decrypt_impl,
    attrs = {
        "extracted_dir": attrs.source(),
        "key": attrs.string(),
        "output_name": attrs.option(attrs.string(), default = None),
        "ipsw_tool": attrs.exec_dep(default = "//src/tools/ipsw:ipsw"),
    },
)

def _make_disk_image_impl(ctx):
    out = ctx.actions.declare_output(ctx.attrs.output_name or "disk.img")
    
    cmd = [
        ctx.attrs.make_disk_tool[RunInfo],
        "--ios-dmg",
        ctx.attrs.rootfs_dmg,
        "--output",
        out.as_output(),
    ]
    
    ctx.actions.run(cmd, category = "make_disk")
    return [DefaultInfo(default_output = out)]

make_disk_image = rule(
    impl = _make_disk_image_impl,
    attrs = {
        "rootfs_dmg": attrs.source(),
        "output_name": attrs.option(attrs.string(), default = None),
        "make_disk_tool": attrs.exec_dep(default = "//src/tools/make-disk:make-disk"),
    },
)
