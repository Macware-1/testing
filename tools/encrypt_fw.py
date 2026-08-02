#!/usr/bin/env python3
"""
encrypt_fw.py  —  Package a raw ARM binary into an encrypted firmware update file.

Output format (.fwu):
  [IV : 16 bytes]
  [AES-128-CBC encrypted payload]

Decrypted payload:
  [FwHeader : 64 bytes]
    magic     : 4  bytes  (0x43414E45 = "CANE", little-endian)
    version   : 4  bytes
    body_size : 4  bytes  (exact byte count of the app binary)
    sha256    : 32 bytes  (SHA-256 of the raw app binary)
    reserved  : 20 bytes  (zeros)
  [app binary : body_size bytes]
  [PKCS7 padding : 1-16 bytes to make total a multiple of 16]

The AES key must match BOOT_AES_KEY in bootloader/include/boot_config.h.

Usage:
  python3 tools/encrypt_fw.py \\
      --input  build/firmware.bin \\
      --output build/firmware.fwu \\
      [--key   000102030405060708090a0b0c0d0e0f] \\
      [--version 1]

Dependencies:  pip install pycryptodome
"""

import argparse
import hashlib
import os
import struct
import sys

FW_HEADER_MAGIC = 0x43414E45  # "CANE"
FW_HEADER_SIZE  = 64

# Default key must match BOOT_AES_KEY in bootloader/include/boot_config.h
DEFAULT_KEY_HEX = "000102030405060708090a0b0c0d0e0f"


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def build_fw_header(version: int, body: bytes) -> bytes:
    sha = hashlib.sha256(body).digest()
    hdr = struct.pack(
        "<III",          # magic, version, body_size  (3 × uint32_t LE)
        FW_HEADER_MAGIC,
        version,
        len(body),
    )
    hdr += sha          # 32 bytes
    hdr += b"\x00" * 20  # reserved
    assert len(hdr) == FW_HEADER_SIZE, f"Header size mismatch: {len(hdr)}"
    return hdr


def encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
    except ImportError:
        sys.exit(
            "ERROR: pycryptodome not found.\n"
            "Install with:  pip install pycryptodome"
        )
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt a firmware binary into a .fwu update package"
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Raw ARM binary (e.g. build/firmware.bin)"
    )
    parser.add_argument(
        "--output", "-o", required=True,
        help="Output encrypted firmware file (e.g. build/firmware.fwu)"
    )
    parser.add_argument(
        "--key", "-k", default=DEFAULT_KEY_HEX,
        help=f"AES-128 key as 32 hex chars (default: {DEFAULT_KEY_HEX})"
    )
    parser.add_argument(
        "--version", "-v", type=int, default=1,
        help="Firmware version number (default: 1)"
    )
    args = parser.parse_args()

    # Parse key
    key_hex = args.key.replace(" ", "").replace("0x", "")
    if len(key_hex) != 32:
        sys.exit(f"ERROR: key must be 16 bytes (32 hex chars), got {len(key_hex)//2}")
    key = bytes.fromhex(key_hex)

    # Read input binary
    try:
        with open(args.input, "rb") as f:
            body = f.read()
    except FileNotFoundError:
        sys.exit(f"ERROR: input file not found: {args.input}")

    if len(body) == 0:
        sys.exit("ERROR: input file is empty")

    max_size = 7 * 128 * 1024  # 896 KB
    if len(body) > max_size:
        sys.exit(
            f"ERROR: firmware too large ({len(body):,} bytes). "
            f"Maximum is {max_size:,} bytes (896 KB, Bank 1 sectors 1-7)."
        )

    # Build payload
    header    = build_fw_header(args.version, body)
    payload   = pkcs7_pad(header + body)
    iv        = os.urandom(16)
    encrypted = encrypt(key, iv, payload)

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(iv)
        f.write(encrypted)

    sha256 = hashlib.sha256(body).hexdigest()
    print(f"Input:      {args.input}  ({len(body):,} bytes)")
    print(f"SHA-256:    {sha256}")
    print(f"Version:    {args.version}")
    print(f"IV:         {iv.hex()}")
    print(f"Output:     {args.output}  ({16 + len(encrypted):,} bytes)")
    print("Done.")


if __name__ == "__main__":
    main()
