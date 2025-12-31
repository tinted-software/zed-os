#!/bin/bash
# Build disk image for GravityOS
# Contains shared cache at offset 0 and rootfs.tar at 400MB

set -e

IOS_ROOT="/Volumes/Telluride9A405.K48OS"
DISK_IMG="disk.img"
DISK_SIZE=$((512 * 1024 * 1024))  # 512MB

echo "Creating disk image..."
dd if=/dev/zero of="$DISK_IMG" bs=1M count=512 2>/dev/null

echo "Copying shared cache..."
SHARED_CACHE="$IOS_ROOT/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7"
if [ -f "$SHARED_CACHE" ]; then
    dd if="$SHARED_CACHE" of="$DISK_IMG" conv=notrunc 2>/dev/null
    echo "Shared cache written ($(stat -f%z "$SHARED_CACHE") bytes)"
else
    echo "WARNING: Shared cache not found at $SHARED_CACHE"
    echo "Creating empty placeholder..."
fi

echo "Creating rootfs.tar..."
ROOTFS_DIR="rootfs"
mkdir -p "$ROOTFS_DIR/bin"
mkdir -p "$ROOTFS_DIR/usr/lib"

# Copy some binaries
if [ -d "$IOS_ROOT" ]; then
    cp "$IOS_ROOT/bin/ls" "$ROOTFS_DIR/bin/" 2>/dev/null || true
    cp "$IOS_ROOT/bin/cat" "$ROOTFS_DIR/bin/" 2>/dev/null || true
    cp "$IOS_ROOT/bin/echo" "$ROOTFS_DIR/bin/" 2>/dev/null || true
    cp "$IOS_ROOT/usr/lib/dyld" "$ROOTFS_DIR/usr/lib/" 2>/dev/null || true
fi

# Create tar archive
tar cf rootfs.tar -C "$ROOTFS_DIR" .
echo "Rootfs created ($(stat -f%z rootfs.tar) bytes)"

# Write rootfs at 400MB offset
dd if=rootfs.tar of="$DISK_IMG" bs=1M seek=400 conv=notrunc 2>/dev/null

echo "Disk image created: $DISK_IMG"
ls -lh "$DISK_IMG"

# Cleanup
rm -rf "$ROOTFS_DIR" rootfs.tar

echo "Done!"
