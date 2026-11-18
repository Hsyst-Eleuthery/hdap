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
# The GNU target is linked against glibc 2.28 (Zig's sysroot) instead of the
# host glibc. A native build on a recent runner emits GLIBC_2.43 symbols and
# then fails on ordinary desktops such as Ubuntu 24.04 (glibc 2.39).
#
# The musl package is headless by design: a static musl binary cannot dlopen
# the system Wayland/X11 libraries that winit needs, so hdap-gui is omitted.
# Use the GNU package for the graphical interface.
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
    # setup-zig (CI) and most local installs put zig on PATH; check it first.
    if command -v zig >/dev/null 2>&1; then
        command -v zig
        return 0
    fi
    for p in "$HOME/.local/zig"/*/zig "$HOME/.local/zig/bin/zig" /usr/local/bin/zig /usr/bin/zig; do
        if [[ -x "$p" ]]; then echo "$p"; return 0; fi
    done
    echo ""
}

# GNU gets an explicit old glibc baseline; the other targets use the triple
# as given. Zig is required for every package now, including GNU.
case "$TARGET" in
    x86_64-unknown-linux-gnu) BUILD_TARGET="$TARGET.2.28" ;;
    *)                        BUILD_TARGET="$TARGET" ;;
esac

ZIG="$(find_zig)"
if [[ -z "$ZIG" ]]; then
    echo "error: zig not found (install to ~/.local/zig, see header)" >&2
    exit 1
fi
export PATH="$(dirname "$ZIG"):$PATH"

echo "==> cross-compiling for $BUILD_TARGET (zig: $ZIG)"
cargo zigbuild --release --manifest-path "$ROOT/Cargo.toml" --target "$BUILD_TARGET" --workspace --bins

# cargo-zigbuild may keep or strip the glibc suffix in the output directory.
BIN_DIR="$ROOT/target/$BUILD_TARGET/release"
if [[ ! -f "$BIN_DIR/hdap-server" ]]; then
    BIN_DIR="$ROOT/target/${BUILD_TARGET%%.*}/release"
fi

rm -rf "$STAGE"
mkdir -p "$STAGE"

# Static musl cannot dlopen Wayland/X11, so shipping hdap-gui there would
# only deliver a binary that always fails on the desktop.
BINS=(hdap-server hdap-cli)
if [[ "$TARGET" != *musl* ]]; then
    BINS+=(hdap-gui)
fi

for bin in "${BINS[@]}"; do
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

if [[ "$TARGET" == *musl* ]]; then
    cat > "$STAGE/AVISO-GUI.txt" <<'EOF'
Este pacote musl e estatico e nao inclui hdap-gui. Um binario estatico nao
consegue carregar as bibliotecas Wayland/X11 do sistema (winit usa dlopen),
entao a interface grafica sempre falharia com NoWaylandLib / Dynamic loading
not supported. Use o pacote x86_64-unknown-linux-gnu para a interface grafica.

This static musl package does not include hdap-gui: a static binary cannot
dlopen the system Wayland/X11 libraries that winit needs. Use the
x86_64-unknown-linux-gnu package for the graphical interface.
EOF
fi

(
    cd "$STAGE"
    FILES=(hdap-*)
    if [[ -f AVISO-GUI.txt ]]; then FILES+=(AVISO-GUI.txt); fi
    sha256sum "${FILES[@]}" > SHA256SUMS
)

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
