#!/usr/bin/env python3
"""
config_tool.py  — Diagnose and update CAN-ETH Gateway configuration.

Works directly over HTTP/msgpack — no browser required.

Usage:
    # Print current config stored on device
    python tools/config_tool.py --ip 121.145.35.64 show

    # Save current config back to flash (round-trip test)
    python tools/config_tool.py --ip 121.145.35.64 save

    # Change one or more fields then save
    python tools/config_tool.py --ip 121.145.35.64 save --set board.eth_ip=192.168.1.100
    python tools/config_tool.py --ip 121.145.35.64 save --set board.eth_ip=192.168.1.100 --set can.j1939=1

    # Just fetch and dump the raw msgpack response (hex)
    python tools/config_tool.py --ip 121.145.35.64 dump

Requirements:
    pip install requests msgpack
"""

import sys
import time
import struct
import argparse
import json

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

try:
    import msgpack
except ImportError:
    sys.exit("pip install msgpack")


# ── IP helpers ─────────────────────────────────────────────────────────────────

def ip_to_list(ip_str):
    """'192.168.1.1' → [192, 168, 1, 1]"""
    return [int(x) for x in ip_str.split('.')]

def list_to_ip(lst):
    """[192, 168, 1, 1] → '192.168.1.1'"""
    return '.'.join(str(b) for b in lst)


# ── Config fetch / post ────────────────────────────────────────────────────────

def fetch_config(base_url: str) -> dict:
    """GET /api/config/values → decoded msgpack dict."""
    url = base_url + "/api/config/values"
    print(f"  GET {url}")
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    data = r.content
    print(f"  Response: {len(data)} bytes")
    cfg = msgpack.unpackb(data, raw=False)
    return cfg


def post_config(base_url: str, cfg: dict) -> dict:
    """POST msgpack to /api/sendconfig. Returns firmware JSON response."""
    url = base_url + "/api/sendconfig"
    payload = msgpack.packb(cfg, use_bin_type=True)
    print(f"  POST {url}  ({len(payload)} bytes)")
    r = requests.post(
        url,
        data=payload,
        headers={"Content-Type": "application/octet-stream"},
        timeout=10,
    )
    # Don't raise_for_status — print the body regardless
    print(f"  HTTP {r.status_code}")
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}
    return body


def wait_for_reboot(base_url: str, timeout_s: int = 30):
    """Poll /api/info until the device responds after a reboot."""
    url = base_url + "/api/info"
    print(f"  Waiting for device to reboot", end="", flush=True)
    deadline = time.time() + timeout_s
    # First wait until it goes away (optional — some fast boards come back immediately)
    time.sleep(0.5)
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.ok:
                print(" ✓ online")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(1)
    print(" ✗ timed out")
    return False


# ── Field setter ───────────────────────────────────────────────────────────────

def apply_set(cfg: dict, key_val: str):
    """Apply 'section.field=value' to cfg dict in-place.

    Examples:
        board.eth_ip=192.168.1.100   → cfg['board']['eth_ip'] = [192,168,1,100]
        can.j1939=1                  → cfg['can']['j1939'] = 1
        can.nbrp=2                   → cfg['can']['nbrp'] = 2
        board.ptp_enable=0           → cfg['board']['ptp_enable'] = 0
    """
    if '=' not in key_val:
        print(f"  [WARN] ignoring --set {key_val!r} (no '=' found)")
        return

    path, raw_val = key_val.split('=', 1)
    parts = path.strip().split('.')
    if len(parts) != 2:
        print(f"  [WARN] --set must be 'section.field=value', got: {key_val!r}")
        return

    section, field = parts

    # Auto-convert value type
    # IP arrays (4 octets)
    if '.' in raw_val and raw_val.count('.') == 3:
        try:
            value = ip_to_list(raw_val)
        except Exception:
            value = raw_val
    else:
        # Try int first, then string
        try:
            value = int(raw_val)
        except ValueError:
            value = raw_val

    if section not in cfg:
        print(f"  [WARN] section '{section}' not in config — skipping")
        return

    old = cfg[section].get(field, '<missing>')
    cfg[section][field] = value
    print(f"  Set {section}.{field}: {old!r} → {value!r}")


# ── Pretty printer ─────────────────────────────────────────────────────────────

def pretty_cfg(cfg: dict):
    """Print config in a readable format, converting IP arrays to strings."""
    IP_FIELDS = {'eth_ip', 'eth_mask', 'eth_gw', 'usb_ip', 'radxa_dest_ip'}

    for section, fields in cfg.items():
        print(f"\n[{section}]")
        if isinstance(fields, dict):
            for k, v in fields.items():
                # Nested section (e.g. filters.r0, logging.ch1)
                if isinstance(v, dict):
                    print(f"  [{k}]")
                    for kk, vv in v.items():
                        if isinstance(vv, list) and len(vv) == 4 and kk in IP_FIELDS:
                            print(f"      {kk:20s} = {list_to_ip(vv)}")
                        else:
                            print(f"      {kk:20s} = {vv!r}")
                elif isinstance(v, list) and len(v) == 4 and k in IP_FIELDS:
                    print(f"  {k:22s} = {list_to_ip(v)}")
                else:
                    print(f"  {k:22s} = {v!r}")


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_show(base_url, args):
    print("\n=== Fetching config ===")
    try:
        cfg = fetch_config(base_url)
    except Exception as e:
        print(f"  ERROR: {e}")
        return 1
    pretty_cfg(cfg)
    return 0


def cmd_dump(base_url, args):
    """Dump raw msgpack bytes as hex — useful to see exactly what the device returns."""
    url = base_url + "/api/config/values"
    print(f"\n=== Raw msgpack dump from {url} ===")
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
    except Exception as e:
        print(f"  ERROR: {e}")
        return 1
    data = r.content
    print(f"  {len(data)} bytes:")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04x}  {hex_part:<48s}  {ascii_part}")
    return 0


def cmd_save(base_url, args):
    print("\n=== Fetching current config ===")
    try:
        cfg = fetch_config(base_url)
    except Exception as e:
        print(f"  ERROR fetching config: {e}")
        return 1

    # Apply any --set overrides
    for kv in (args.set or []):
        apply_set(cfg, kv)

    print("\n=== Posting config to device ===")
    resp = post_config(base_url, cfg)
    print(f"  Firmware response: {json.dumps(resp)}")

    if resp.get("status") == "error":
        print(f"\n  ✗ SAVE FAILED: {resp.get('msg', '?')}")
        print("\n  Possible causes:")
        print("    - 'bad msgpack'      → msgpack encoding mismatch between tool and firmware")
        print("    - 'flash write failed' → hardware issue writing to flash")
        print("    - 'empty body'       → request body not received by firmware")
        return 1

    print(f"\n  ✓ Save OK — device is rebooting...")
    if wait_for_reboot(base_url):
        print("\n=== Verifying saved config ===")
        try:
            new_cfg = fetch_config(base_url)
            pretty_cfg(new_cfg)
        except Exception as e:
            print(f"  ERROR reading back config: {e}")
    return 0


def cmd_info(base_url, args):
    print(f"\n=== Device info from {base_url}/api/info ===")
    try:
        r = requests.get(base_url + "/api/info", timeout=5)
        r.raise_for_status()
        info = r.json()
        for k, v in info.items():
            print(f"  {k:15s} = {v}")
    except Exception as e:
        print(f"  ERROR: {e}")
        return 1
    return 0


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CAN-ETH Gateway config diagnostic tool"
    )
    parser.add_argument("--ip",   default="121.145.35.64",
                        help="Gateway IP address (default: 121.145.35.64)")
    parser.add_argument("--port", default=80, type=int,
                        help="HTTP port (default: 80)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("show",  help="Fetch and pretty-print current config")
    sub.add_parser("dump",  help="Dump raw msgpack hex from device")
    sub.add_parser("info",  help="Print /api/info fields")

    p_save = sub.add_parser("save", help="Fetch config, optionally modify fields, save to flash")
    p_save.add_argument("--set", action="append", metavar="section.field=value",
                        help="Override a config field (repeatable). "
                             "E.g.: --set board.eth_ip=192.168.1.100 --set can.j1939=1")

    args = parser.parse_args()
    base_url = f"http://{args.ip}:{args.port}"
    print(f"Gateway: {base_url}")

    cmds = {"show": cmd_show, "dump": cmd_dump, "save": cmd_save, "info": cmd_info}
    return cmds[args.cmd](base_url, args)


if __name__ == "__main__":
    sys.exit(main() or 0)
