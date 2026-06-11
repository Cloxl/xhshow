import base64
import gzip
import json
import random
import struct
import time
from collections.abc import Mapping
from typing import Any

from ..config import CryptoConfig
from ..utils.hash import xxh32
from ..utils.random_gen import RandomGenerator

__all__ = ["x_rap_param"]

_cfg = CryptoConfig()
_MASK_32 = _cfg.MAX_32BIT
_XRAP_SDK_VERSION = _cfg.XRAP_SDK_VERSION

# SM4-variant round keys (pre-expanded, 10 rounds)
_ROUND_KEYS: tuple[tuple[int, int, int, int], ...] = (
    (0x6B714931, 0x44546377, 0x4B583930, 0x5A744179),
    (0x89314C98, 0xCD652FEF, 0x863D16DF, 0xDC4957A6),
    (0xC205330C, 0x0F601CE3, 0x895D0A3C, 0x55145D9A),
    (0xD205006E, 0xDD651C8D, 0x543816B1, 0x012C4B2B),
    (0x770C2B6F, 0xAA6937E2, 0xFE512153, 0xFF7D6A78),
    (0x7866FBF4, 0xD20FCC16, 0x2C5EED45, 0xD323873D),
    (0x90E9C67E, 0x42E60A68, 0x6EB8E72D, 0xBD9B6010),
    (0xE9C52BEE, 0xAB232186, 0xC59BC6AB, 0x7800A6BB),
    (0x13BA9A3E, 0xB899BBB8, 0x7D027D13, 0x0502DBA8),
    (0x50613270, 0xE8F889C8, 0x95FAF4DB, 0x90F82F73),
)
_LAST_ROUND_KEY = (0xF396B44F, 0x1B6E3D87, 0x8E94C95C, 0x1E6CE62F)
_LAST_ROUND_KEY_BYTES = b"".join(w.to_bytes(4, "big") for w in _LAST_ROUND_KEY)

# fmt: off
# Non-linear substitution box (256 entries)
_SBOX = (
    0x7A, 0x01, 0x58, 0xE0, 0x50, 0x4E, 0x02, 0x79, 0x1D, 0x4B, 0x53, 0xDA, 0x6B, 0x48, 0xD4, 0x52,
    0xED, 0x77, 0x12, 0x21, 0x14, 0x15, 0xEC, 0x10, 0x18, 0xE5, 0xB9, 0xF1, 0x0C, 0x08, 0xFC, 0x7D,
    0xF9, 0xCD, 0xB5, 0xC8, 0xE6, 0x37, 0x26, 0x87, 0x56, 0xBA, 0xB8, 0x2B, 0xAD, 0xF0, 0x68, 0xF7,
    0x8B, 0x8D, 0xD3, 0x5E, 0x36, 0x4D, 0x2E, 0x92, 0x31, 0x82, 0xF2, 0x29, 0x70, 0x3D, 0x2D, 0xD7,
    0xB6, 0x40, 0xB2, 0x43, 0x44, 0x80, 0x78, 0xD2, 0x0D, 0x49, 0x4A, 0x09, 0x63, 0x6C, 0x07, 0x3A,
    0x9E, 0xD5, 0x06, 0xC6, 0xE1, 0x62, 0xF4, 0x34, 0x24, 0x59, 0xA9, 0x57, 0x2A, 0x00, 0x3E, 0x17,
    0x2C, 0x0A, 0x1A, 0x42, 0xFA, 0x93, 0xBE, 0xDC, 0xF5, 0xB3, 0x6A, 0x13, 0xE8, 0x03, 0xC7, 0x97,
    0xBB, 0x73, 0x76, 0x86, 0xE3, 0x46, 0x72, 0x47, 0xD0, 0x05, 0x4C, 0x38, 0x7C, 0x1F, 0x81, 0xAB,
    0x75, 0x51, 0xEB, 0xF3, 0x32, 0x74, 0x11, 0x8F, 0x84, 0x89, 0x9C, 0x71, 0x22, 0x7E, 0x9D, 0xCF,
    0x3F, 0x91, 0x69, 0x65, 0x3C, 0x6D, 0x96, 0xA2, 0x98, 0x99, 0x33, 0x39, 0x9A, 0xCA, 0xC3, 0x9F,
    0xA0, 0xBC, 0xE4, 0xA3, 0xA4, 0x54, 0x7F, 0xA7, 0xA8, 0x04, 0x6F, 0x5D, 0xAC, 0xB7, 0x27, 0xAF,
    0xB0, 0x28, 0x41, 0xAE, 0xB4, 0x6E, 0x0B, 0x1B, 0xDF, 0x8E, 0x30, 0xB1, 0xFE, 0x90, 0x61, 0x60,
    0xC0, 0xCB, 0x5C, 0x0E, 0xEF, 0x16, 0x83, 0xEA, 0x20, 0xE9, 0xC9, 0x55, 0xC4, 0x45, 0x85, 0xCC,
    0x1E, 0xAA, 0x67, 0x8A, 0x7B, 0x35, 0xD6, 0x19, 0xD8, 0xD9, 0xC2, 0xDB, 0x94, 0xDD, 0x1C, 0xDE,
    0xA6, 0xFF, 0xF8, 0xBF, 0x5B, 0x5A, 0x0F, 0xE7, 0xC1, 0xBD, 0xD1, 0x66, 0xC5, 0x25, 0xEE, 0x8C,
    0xE2, 0x5F, 0x88, 0xA1, 0x3B, 0xA5, 0xF6, 0xCE, 0x95, 0x2F, 0x64, 0x23, 0xFB, 0xFD, 0x4F, 0x9B,
)
# fmt: on


# --- GF(2^8) helpers for T-table generation ---


def _gf_double(x: int) -> int:
    x <<= 1
    return (x ^ 0x11B) & 0xFF if x & 0x100 else x & 0xFF


def _gf_mul(x: int, n: int) -> int:
    if n == 1:
        return x
    if n == 2:
        return _gf_double(x)
    if n == 3:
        return _gf_double(x) ^ x
    raise ValueError(f"unsupported GF multiplier: {n}")


def _build_lookup_tables() -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    """Pre-compute 4 shifted T-tables from the S-box for the round function."""
    col0: list[int] = []
    col1: list[int] = []
    col2: list[int] = []
    col3: list[int] = []
    for s in _SBOX:
        a, d = _gf_mul(s, 2), _gf_mul(s, 3)
        col0.append(((a << 24) | (s << 16) | (s << 8) | d) & _MASK_32)
        col1.append(((d << 24) | (a << 16) | (s << 8) | s) & _MASK_32)
        col2.append(((s << 24) | (d << 16) | (a << 8) | s) & _MASK_32)
        col3.append(((s << 24) | (s << 16) | (d << 8) | a) & _MASK_32)
    return tuple(col0), tuple(col1), tuple(col2), tuple(col3)


_LUT0, _LUT1, _LUT2, _LUT3 = _build_lookup_tables()


# --- Bit-level utilities ---


def _read_u32be(buf: bytes | bytearray | memoryview, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 4], "big")


def _to_compact_json(data: Mapping[str, Any] | str | bytes | bytearray) -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, bytes | bytearray):
        return bytes(data).decode("utf-8")
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


# --- TLV field writers for the body structure ---


def _field_byte(tag: int, val: int = 0) -> bytes:
    return struct.pack(">H", tag) + bytes((val,))


def _field_u32(tag: int, val: int) -> bytes:
    return struct.pack(">HI", tag, val)


def _field_u64(tag: int, val: int) -> bytes:
    return struct.pack(">H", tag) + val.to_bytes(8, "big", signed=False)


def _field_blob(tag: int, data: bytes) -> bytes:
    return struct.pack(">HI", tag, len(data)) + data


# --- Block cipher (SM4-variant with custom S-box and round keys) ---


def encrypt_block16(block: bytes | bytearray | memoryview) -> bytes:
    """Encrypt a single 16-byte block; shorter input is zero-padded on the right."""
    src = bytes(block)
    if len(src) > 16:
        raise ValueError("block length must be <= 16")
    padded = src.ljust(16, b"\x00")
    s0 = (_read_u32be(padded, 0) ^ _ROUND_KEYS[0][0]) & _MASK_32
    s1 = (_read_u32be(padded, 4) ^ _ROUND_KEYS[0][1]) & _MASK_32
    s2 = (_read_u32be(padded, 8) ^ _ROUND_KEYS[0][2]) & _MASK_32
    s3 = (_read_u32be(padded, 12) ^ _ROUND_KEYS[0][3]) & _MASK_32

    for rnd in range(1, 10):
        rk = _ROUND_KEYS[rnd]
        n0 = (
            _LUT0[(s0 >> 24) & 0xFF] ^ _LUT1[(s1 >> 16) & 0xFF] ^ _LUT2[(s2 >> 8) & 0xFF] ^ _LUT3[s3 & 0xFF] ^ rk[0]
        ) & _MASK_32
        n1 = (
            _LUT0[(s1 >> 24) & 0xFF] ^ _LUT1[(s2 >> 16) & 0xFF] ^ _LUT2[(s3 >> 8) & 0xFF] ^ _LUT3[s0 & 0xFF] ^ rk[1]
        ) & _MASK_32
        n2 = (
            _LUT0[(s2 >> 24) & 0xFF] ^ _LUT1[(s3 >> 16) & 0xFF] ^ _LUT2[(s0 >> 8) & 0xFF] ^ _LUT3[s1 & 0xFF] ^ rk[2]
        ) & _MASK_32
        n3 = (
            _LUT0[(s3 >> 24) & 0xFF] ^ _LUT1[(s0 >> 16) & 0xFF] ^ _LUT2[(s1 >> 8) & 0xFF] ^ _LUT3[s2 & 0xFF] ^ rk[3]
        ) & _MASK_32
        s0, s1, s2, s3 = n0, n1, n2, n3

    state = (s0, s1, s2, s3)
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            idx = (state[(row + col) & 3] >> (24 - 8 * col)) & 0xFF
            out[4 * row + col] = _SBOX[idx] ^ _LAST_ROUND_KEY_BYTES[4 * row + col]
    return bytes(out)


def _encrypt_blocks(src: bytes) -> bytes:
    """Encrypt data by splitting into 16-byte blocks (ECB mode)."""
    return b"".join(encrypt_block16(src[i : i + 16]) for i in range(0, len(src), 16))


def _encrypt_session_key(key: bytes) -> bytes:
    """Encrypt the 16-byte session key and append its length."""
    if len(key) != 16:
        raise ValueError("session key must be 16 bytes")
    return encrypt_block16(key) + struct.pack(">I", 16)


# --- Default environment snapshots (stable across PC runtime versions) ---

_DEFAULT_INTERACTION_TRACE = bytes.fromhex(
    "0002000200004700000000000001ffd9ffa8005c23fff1ffff001501ff90fff9000022fff2ffff"
    "001501ffb800770061a5ffe3ffff002a01fffcffe70000f0ffe4ffff002a01ffd30000003e01"
    "ffd40000003e01ffc8ffff005301ffbdfffa006901ffbefffb006901ffb1fff4007d01ffa6ff"
    "ee009301ffa8ffef009301ff9effe900a801ff96ffe600be01ff97ffe600be01ff93ffe500d3"
    "01ff92ffe500ea01ff92ffe4010501ff92ffe3011b01ff92ffe402d101ff93ffe502f201ff94"
    "ffe6040501"
)

_DEFAULT_ENVIRONMENT_SNAPSHOT = bytes.fromhex(
    "000000010000000000000000fffeffff00000000000000390001ffff00bc00000000006e0002"
    "0001013400000000012f00000002011a00000000016100000000019f000000000247000000000279"
    "0000000002b1"
)


# --- Body structure builder ---


def _build_body_structure(
    api: str,
    data: Mapping[str, Any] | str | bytes | bytearray,
    *,
    session_key: str | bytes | bytearray | None = None,
    timestamp_ms: int | None = None,
    nonce: int | None = None,
    obfuscation_byte: int | None = None,
    interaction_trace: bytes | bytearray | memoryview | None = None,
    environment_snapshot: bytes | bytearray | memoryview | None = None,
) -> bytes:
    """Build the pre-compression TLV payload for the RAP parameter."""
    body_str = _to_compact_json(data)
    hash_input = (api + body_str).encode("utf-8")
    ts = int(time.time() * 1000) if timestamp_ms is None else int(timestamp_ms)
    key = (
        session_key.encode("ascii")
        if isinstance(session_key, str)
        else bytes(session_key or RandomGenerator.generate_random_ascii(16).encode("ascii"))
    )
    if len(key) != 16:
        raise ValueError("session_key must be 16 bytes")
    xor_byte = random.randrange(1, 256) if obfuscation_byte is None else (obfuscation_byte & 0xFF)
    rand_nonce = random.getrandbits(32) if nonce is None else (int(nonce) & _MASK_32)

    trace = bytes(interaction_trace if interaction_trace is not None else _DEFAULT_INTERACTION_TRACE)
    env = bytes(environment_snapshot if environment_snapshot is not None else _DEFAULT_ENVIRONMENT_SNAPSHOT)

    buf = bytearray()
    buf += _field_u64(0x03E8, ts)
    buf += _field_u32(0x03E9, rand_nonce)
    buf += _field_blob(0x03EA, key)
    buf += _field_u32(0x03EB, xxh32(hash_input))

    # Boolean capability flags
    for tag in list(range(1051, 1066)) + [1070] + list(range(1066, 1070)):
        buf += _field_byte(tag)
    buf += _field_u32(1100, 0)
    for tag in range(1071, 1074):
        buf += _field_byte(tag)

    # Runtime timing and environment fields
    buf += _field_u32(1075, 0x564)
    buf += _field_u32(1076, 0x2C)
    buf += _field_u64(1077, max(0, ts - 0x434))
    buf += _field_blob(1078, trace)

    buf += _field_u32(1082, 0)
    buf += _field_u32(1084, 0)
    buf += _field_u32(1085, 0)
    buf += _field_u32(1086, 100)
    buf += _field_u64(1087, max(0, ts - 0x2D7))
    buf += _field_blob(1088, env)

    buf += _field_u32(1090, 0)
    buf += _field_u32(1097, 0)
    buf += _field_u32(1092, 0x566)
    buf += _field_u32(1094, 0x519)
    buf += _field_u64(1095, max(0, ts - 0x218C))
    buf += _field_u32(1093, 0)
    buf += _field_byte(1096)
    buf += _field_blob(1091, b"\x00\x00\xff\xff")
    for tag in range(1151, 1157):
        buf += _field_byte(tag)

    # First 16 bytes remain cleartext; rest is XOR-obfuscated
    return bytes(buf[:16] + bytes((b ^ xor_byte) for b in buf[16:]))


def _compress_body(raw: bytes, *, mtime: int | None = None, level: int = 6) -> bytes:
    """Gzip-compress with OS byte patched to match the browser runtime (0x03)."""
    if mtime is None:
        mtime = int(time.time())
    out = bytearray(gzip.compress(raw, compresslevel=level, mtime=mtime))
    if len(out) >= 10:
        out[9] = 0x03
    return bytes(out)


def _cyclic_xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _pack_envelope(
    compressed: bytes,
    *,
    encryption_key: str | bytes | bytearray | None = None,
    salt_string: str | None = None,
    processing_time: int | None = None,
    protocol_version: int = _XRAP_SDK_VERSION,
) -> str:
    """Encrypt, wrap, and base64-encode the compressed body into the final x-rap-param."""
    gz = bytes(compressed)
    key = (
        encryption_key.encode("ascii")
        if isinstance(encryption_key, str)
        else bytes(encryption_key or RandomGenerator.generate_random_ascii(16).encode("ascii"))
    )
    if len(key) != 16:
        raise ValueError("encryption_key must be 16 bytes")
    salt = salt_string if salt_string is not None else RandomGenerator.generate_random_ascii(random.choice((4, 5, 6)))
    salt_bytes = salt.encode("ascii")
    if not 0 <= len(salt_bytes) <= 255:
        raise ValueError("salt_string length must fit one byte")

    xored = _cyclic_xor(gz, key)
    cipher_blocks = _encrypt_blocks(xored)
    cipher_body = cipher_blocks + struct.pack(">I", len(gz))
    content = salt_bytes + _encrypt_session_key(key) + cipher_body
    content_hash = xxh32(content)
    enc_time = int(processing_time if processing_time is not None else random.randint(60, 240))

    header = (
        bytes((0x07, 0x24, 0x01, len(salt_bytes)))
        + struct.pack(">I", 1)
        + struct.pack(">I", 20)
        + struct.pack(">I", len(cipher_body))
        + struct.pack(">I", content_hash)
        + struct.pack(">I", protocol_version)
        + struct.pack(">I", enc_time)
        + b"\x00" * 8
    )
    return base64.b64encode(header + content).decode("ascii")


def x_rap_param(
    api: str,
    data: Mapping[str, Any] | str | bytes | bytearray,
    *,
    aes_key: str | bytes | bytearray | None = None,
    random_string: str | None = None,
    inner_key: str | bytes | bytearray | None = None,
    timestamp_ms: int | None = None,
    body_rand32: int | None = None,
    mask: int | None = None,
    trace_payload: bytes | bytearray | memoryview | None = None,
    env_payload: bytes | bytearray | memoryview | None = None,
    gzip_mtime: int | None = None,
    body_encry_time: int | None = None,
    sdk_version: int = _XRAP_SDK_VERSION,
    compresslevel: int = 6,
) -> str:
    """
    Generate x-rap-param from API path and request payload (pure Python).

    Args:
        api: Request API path (e.g. "//edith.xiaohongshu.com/api/sns/web/v1/feed")
        data: Request body as dict, JSON string, or raw bytes
        aes_key: Optional fixed 16-byte encryption key (random if omitted)
        random_string: Optional fixed salt string (random 4-6 chars if omitted)
        inner_key: Optional fixed 16-byte session key for body structure (random if omitted)
        timestamp_ms: Optional fixed timestamp in milliseconds (current time if omitted)
        body_rand32: Optional fixed 32-bit nonce (random if omitted)
        mask: Optional fixed XOR obfuscation byte (random 1-255 if omitted)
        trace_payload: Optional custom interaction trace bytes
        env_payload: Optional custom environment snapshot bytes
        gzip_mtime: Optional fixed gzip mtime in seconds
        body_encry_time: Optional fixed processing time value
        sdk_version: Protocol version number (default 10300)
        compresslevel: Gzip compression level (default 6)

    Returns:
        Base64-encoded x-rap-param string
    """
    raw_body = _build_body_structure(
        api,
        data,
        session_key=inner_key,
        timestamp_ms=timestamp_ms,
        nonce=body_rand32,
        obfuscation_byte=mask,
        interaction_trace=trace_payload,
        environment_snapshot=env_payload,
    )
    compressed = _compress_body(raw_body, mtime=gzip_mtime, level=compresslevel)
    return _pack_envelope(
        compressed,
        encryption_key=aes_key,
        salt_string=random_string,
        processing_time=body_encry_time,
        protocol_version=sdk_version,
    )
