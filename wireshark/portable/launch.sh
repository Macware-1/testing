#!/usr/bin/env bash
# launch.sh — Launch Wireshark with CLOG plugin, portable (no install)
#
# Sets WIRESHARK_HOME to a local folder so nothing is written to ~/.config/wireshark.
# Useful when sharing a USB drive or working on a machine you don't own.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WS_HOME="$SCRIPT_DIR/WiresharkHome"
PLUGIN_DIR="$WS_HOME/plugins"

mkdir -p "$PLUGIN_DIR"

# Copy all Lua plugins and color rules from parent
cp -f "$SCRIPT_DIR"/../*.lua "$PLUGIN_DIR/"
cp -f "$SCRIPT_DIR/../colorfilters" "$WS_HOME/"

export WIRESHARK_HOME="$WS_HOME"
echo "WIRESHARK_HOME = $WS_HOME"
echo "Launching Wireshark with capture filter: udp port 47808"
echo ""

# Launch Wireshark; -k starts capture immediately, -f sets capture filter
wireshark -k -f "udp port 47808 or udp port 7898" &
