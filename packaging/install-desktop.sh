#!/usr/bin/env bash
# install-desktop.sh — add CheckHook to the application menu: the desktop app
# ("CheckHook") and the terminal launcher ("CheckHook (terminal)", Kali style).
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
DESKTOP_TERM="$APPS/checkhook-terminal.desktop"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -f "$DESKTOP" "$DESKTOP_TERM" "$ICON_SVG_DIR/checkhook.svg" "$ICON_PNG_DIR/checkhook.png"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
  echo "CheckHook desktop entry removed."
  exit 0
fi

mkdir -p "$APPS" "$ICON_SVG_DIR" "$ICON_PNG_DIR"

# make sure the launcher is executable
chmod +x "$ROOT/bin/checkhook" "$ROOT/bin/checkhookd" 2>/dev/null || true

# install icons
install -m 0644 "$ROOT/assets/checkhook.svg" "$ICON_SVG_DIR/checkhook.svg"
if [[ -f "$ROOT/assets/checkhook-256.png" ]]; then
  install -m 0644 "$ROOT/assets/checkhook-256.png" "$ICON_PNG_DIR/checkhook.png"
fi

# write the .desktop with absolute paths substituted in
for pair in "checkhook.desktop:$DESKTOP" "checkhook-terminal.desktop:$DESKTOP_TERM"; do
  sed -e "s|__CHECKHOOK_DIR__|$ROOT|g" -e "s|__CHECKHOOK_ICON__|checkhook|g" \
      "$ROOT/packaging/${pair%%:*}" > "${pair#*:}"
  chmod 0644 "${pair#*:}"
done

# refresh the desktop + icon caches (best effort)
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "Installed:"
echo "  $DESKTOP  (app)"
echo "  $DESKTOP_TERM  (terminal)"
echo "  $ICON_SVG_DIR/checkhook.svg"
[[ -f "$ICON_PNG_DIR/checkhook.png" ]] && echo "  $ICON_PNG_DIR/checkhook.png"
echo
echo "CheckHook should now appear in your application menu under Security/Network."
echo "If it doesn't show immediately, log out/in or run:  update-desktop-database $APPS"
if ! python3 -c "import PySide6" 2>/dev/null; then
  echo
  echo "The app needs PySide6 for your user:  python3 -m pip install --user PySide6-Essentials"
fi
if ! command -v pkexec >/dev/null 2>&1; then
  echo "The app asks for root through pkexec (polkit), which is not installed."
fi
