#!/usr/bin/env bash
# setup.sh — Install CLOG Wireshark plugin (Linux / macOS)
#
# Copies clog_dissector.lua and colorfilters into your personal Wireshark
# configuration folder so they are loaded automatically on next start.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Wireshark personal config directory
if [[ "$OSTYPE" == "darwin"* ]]; then
    WS_DIR="$HOME/.config/wireshark"
    # macOS also checks: ~/Library/Application Support/Wireshark
    [[ -d "$HOME/Library/Application Support/Wireshark" ]] && \
        WS_DIR="$HOME/Library/Application Support/Wireshark"
else
    WS_DIR="$HOME/.config/wireshark"
fi

PLUGIN_DIR="$WS_DIR/plugins"
mkdir -p "$PLUGIN_DIR"

# Install all Lua plugins
for lua in "$SCRIPT_DIR"/*.lua; do
    cp -f "$lua" "$PLUGIN_DIR/"
    echo "Installed: $PLUGIN_DIR/$(basename "$lua")"
done

# Install color rules
cp -f "$SCRIPT_DIR/colorfilters" "$WS_DIR/"
echo "Installed: $WS_DIR/colorfilters"

echo ""
echo "============================================================"
echo " CLOG plugin installed."
echo ""
echo " In Wireshark: Analyze → Reload Lua Plugins  (Ctrl+Shift+L)"
echo " Or just restart Wireshark."
echo ""
echo " Capture filter:   udp port 47808 or udp port 7898"
echo " CLOG display filter:   clog"
echo " Status display filter: gwstat"
echo "============================================================"
