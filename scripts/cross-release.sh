#!/usr/bin/env bash
# Cross-compile the HDAP binaries for a target and stage release assets.
#
# Uses cargo-zigbuild + a user-local Zig (no root, no apt):
#   - zig:           https://ziglang.org/download  (extract to ~/.local/zig)
#   - cargo-zigbuild: cargo install cargo-zigbuild
#   - rustup targets: rustup target add <triple>
#
# Usage:
#   ./scripts/cross-release.sh x86_64-unknown-linux-gnu
#   ./scripts/cross-release.sh x86_64-unknown-linux-musl
#   ./scripts/cross-release.sh x86_64-pc-windows-gnu
#
# Output: target/release-assets/<triple>/ plus a compressed archive and
# SHA-256 checksums next to it. Both the individual binaries and the archive
# are kept so they can be uploaded to a GitHub release either way.
set -euo pipefail

TARGET="${1:-x86_64-unknown-linux-musl}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${HDAP_VERSION:-$(grep -m1 '^version = ' "$ROOT/Cargo.toml" | cut -d'"' -f2)}"
ASSETS="$ROOT/target/release-assets"
STAGE="$ASSETS/$TARGET"

find_zig() {
    for p in "$HOME/.local/zig"/*/zig "$HOME/.local/zig/bin/zig" /usr/local/bin/zig /usr/bin/zig; do
        if [[ -x "$p" ]]; then echo "$p"; return 0; fi
    done
    echo ""
}

case "$TARGET" in
    x86_64-unknown-linux-gnu)
        echo "==> native build for $TARGET"
        cargo build --release --manifest-path "$ROOT/Cargo.toml" --workspace --bins
        BIN_DIR="$ROOT/target/release"
        ;;
    *)
        ZIG="$(find_zig)"
        if [[ -z "$ZIG" ]]; then
            echo "error: zig not found (install to ~/.local/zig, see header)" >&2
            exit 1
        fi
        export PATH="$(dirname "$ZIG"):$PATH"
        echo "==> cross-compiling for $TARGET (zig: $ZIG)"
        cargo zigbuild --release --manifest-path "$ROOT/Cargo.toml" --target "$TARGET" --workspace --bins
        BIN_DIR="$ROOT/target/$TARGET/release"
        ;;
esac

rm -rf "$STAGE"
mkdir -p "$STAGE"

for bin in hdap-server hdap-gui hdap-cli; do
    src="$BIN_DIR/$bin"
    if [[ -f "$src.exe" ]]; then src="$src.exe"; fi
    case "$TARGET" in
        *windows*) dst="$bin.exe" ;;
        *) dst="$bin" ;;
    esac
    cp "$src" "$STAGE/$dst"
done

cp "$ROOT/README.md" "$STAGE/README.md"
cp "$ROOT/LICENSE" "$STAGE/LICENSE"

(cd "$STAGE" && sha256sum hdap-* > SHA256SUMS)

case "$TARGET" in
    *windows*)
        ARCHIVE="$ASSETS/hdap-$VERSION-$TARGET.zip"
        rm -f "$ARCHIVE"
        (cd "$STAGE" && zip -q -9 "$ARCHIVE" ./*)
        ;;
    *)
        ARCHIVE="$ASSETS/hdap-$VERSION-$TARGET.tar.gz"
        rm -f "$ARCHIVE"
        tar -C "$STAGE" -czf "$ARCHIVE" .
        ;;
esac

(cd "$ASSETS" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
echo "==> staged $STAGE"
echo "==> archive $ARCHIVE"
