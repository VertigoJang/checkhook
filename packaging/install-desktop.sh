#!/usr/bin/env bash
# install-desktop.sh — add CheckHook to the application menu as a clickable,
# terminal-launching icon (like the Kali tool entries).
#
# Installs for the CURRENT user only (no root needed):
#   ~/.local/share/applications/checkhook.desktop
#   ~/.local/share/icons/hicolor/scalable/apps/checkhook.svg
#   ~/.local/share/icons/hicolor/256x256/apps/checkhook.png   (if available)
#
# Run it from anywhere:  bash packaging/install-desktop.sh
# Uninstall:             bash packaging/install-desktop.sh --uninstall

set -euo pipefail

# repo root = parent of this script's directory
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

APPS="$HOME/.local/share/applications"
ICON_SVG_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
ICON_PNG_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
DESKTOP="$APPS/checkhook.desktop"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -f "$DESKTOP" "$ICON_SVG_DIR/checkhook.svg" "$ICON_PNG_DIR/checkhook.png"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
  echo "CheckHook desktop entry removed."
  exit 0
fi

mkdir -p "$APPS" "$ICON_SVG_DIR" "$ICON_PNG_DIR"

# make sure the launcher is executable
chmod +x "$ROOT/checkhook" 2>/dev/null || true

# install icons
install -m 0644 "$ROOT/assets/checkhook.svg" "$ICON_SVG_DIR/checkhook.svg"
if [[ -f "$ROOT/assets/checkhook-256.png" ]]; then
  install -m 0644 "$ROOT/assets/checkhook-256.png" "$ICON_PNG_DIR/checkhook.png"
fi

# write the .desktop with absolute paths substituted in
sed -e "s|__CHECKHOOK_DIR__|$ROOT|g" \
    -e "s|__CHECKHOOK_ICON__|checkhook|g" \
    "$ROOT/packaging/checkhook.desktop" > "$DESKTOP"
chmod 0644 "$DESKTOP"

# refresh the desktop + icon caches (best effort)
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "Installed:"
echo "  $DESKTOP"
echo "  $ICON_SVG_DIR/checkhook.svg"
[[ -f "$ICON_PNG_DIR/checkhook.png" ]] && echo "  $ICON_PNG_DIR/checkhook.png"
echo
echo "CheckHook should now appear in your application menu under Security/Network."
echo "If it doesn't show immediately, log out/in or run:  update-desktop-database $APPS"
