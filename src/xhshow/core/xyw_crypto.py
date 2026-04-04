import base64
import hashlib
from collections.abc import Sequence

from ..config import CryptoConfig

__all__ = ["XywCipher", "build_xyw_payload_hex"]


S_BOX = (
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


_AES_BLOCK_SIZE = 16


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = _AES_BLOCK_SIZE - (len(data) % _AES_BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _sub_word(word: list[int]) -> list[int]:
    return [S_BOX[value] for value in word]


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != _AES_BLOCK_SIZE:
        raise ValueError("AES-128 requires a 16-byte key")

    words = [list(key[index : index + 4]) for index in range(0, len(key), 4)]
    while len(words) < 44:
        temp = words[-1][:]
        if len(words) % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[len(words) // 4 - 1]
        words.append([left ^ right for left, right in zip(words[-4], temp, strict=False)])

    round_keys: list[list[int]] = []
    for round_index in range(11):
        round_key: list[int] = []
        for word in words[round_index * 4 : (round_index + 1) * 4]:
            round_key.extend(word)
        round_keys.append(round_key)
    return round_keys


def _xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def _mix_single_column(column: list[int]) -> list[int]:
    a0, a1, a2, a3 = column
    return [
        _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3,
        a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3,
        a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3),
        (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3),
    ]


def _add_round_key(state: list[int], round_key: Sequence[int]) -> None:
    for index, key_byte in enumerate(round_key):
        state[index] ^= key_byte


def _sub_bytes(state: list[int]) -> None:
    for index, value in enumerate(state):
        state[index] = S_BOX[value]


def _shift_rows(state: list[int]) -> None:
    for row in range(1, 4):
        row_bytes = [state[row + 4 * column] for column in range(4)]
        row_bytes = row_bytes[row:] + row_bytes[:row]
        for column, value in enumerate(row_bytes):
            state[row + 4 * column] = value


def _mix_columns(state: list[int]) -> None:
    for column in range(4):
        start = column * 4
        state[start : start + 4] = _mix_single_column(state[start : start + 4])


def _encrypt_block(block: bytes, round_keys: Sequence[Sequence[int]]) -> bytes:
    state = list(block)

    _add_round_key(state, round_keys[0])
    for round_key in round_keys[1:-1]:
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_key)

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[-1])
    return bytes(state)


class XywCipher:
    def __init__(self, key: bytes, iv: bytes):
        if len(key) != _AES_BLOCK_SIZE:
            raise ValueError("AES-128 requires a 16-byte key")
        if len(iv) != _AES_BLOCK_SIZE:
            raise ValueError("AES-CBC IV must be 16 bytes")

        self.iv = iv
        self.round_keys = _expand_key(key)

    def encrypt(self, plaintext_bytes: bytes) -> bytes:
        if len(plaintext_bytes) % _AES_BLOCK_SIZE != 0:
            raise ValueError("plaintext_bytes must be PKCS#7 padded to a 16-byte boundary")

        ciphertext_blocks: list[bytes] = []
        previous_block = self.iv

        for offset in range(0, len(plaintext_bytes), _AES_BLOCK_SIZE):
            block = plaintext_bytes[offset : offset + _AES_BLOCK_SIZE]
            chained_block = bytes(left ^ right for left, right in zip(block, previous_block, strict=False))
            encrypted_block = _encrypt_block(chained_block, self.round_keys)
            ciphertext_blocks.append(encrypted_block)
            previous_block = encrypted_block

        return b"".join(ciphertext_blocks)


def build_xyw_payload_hex(
    *,
    full_uri: str,
    a1_value: str,
    timestamp_ms: str,
    config: CryptoConfig,
    env_flags: str | None = None,
) -> str:
    x1 = hashlib.md5(f"url={full_uri}".encode()).hexdigest()
    x2 = env_flags or config.XYW_ENV_FLAGS_DEFAULT
    message = f"x1={x1};x2={x2};x3={a1_value};x4={timestamp_ms};".encode()
    plaintext = _pkcs7_pad(base64.b64encode(message))

    cipher = XywCipher(config.XYW_AES_KEY, config.XYW_AES_IV)
    return cipher.encrypt(plaintext).hex()
