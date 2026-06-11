from ..config import CryptoConfig

__all__ = ["xxh32"]

_MASK_32 = CryptoConfig().MAX_32BIT


def _rotl32(val: int, shift: int) -> int:
    val &= _MASK_32
    return ((val << shift) | (val >> (32 - shift))) & _MASK_32


def xxh32(data: bytes | bytearray | memoryview, seed: int = 0) -> int:
    """Pure Python xxHash32 implementation."""
    buf = bytes(data)
    length = len(buf)
    pos = 0
    prime1 = 0x9E3779B1
    prime2 = 0x85EBCA77
    prime3 = 0xC2B2AE3D
    prime4 = 0x27D4EB2F
    prime5 = 0x165667B1

    if length >= 16:
        acc1 = (seed + prime1 + prime2) & _MASK_32
        acc2 = (seed + prime2) & _MASK_32
        acc3 = seed & _MASK_32
        acc4 = (seed - prime1) & _MASK_32
        end = length - 16
        while pos <= end:
            for acc_ref in (0, 1, 2, 3):
                word = int.from_bytes(buf[pos : pos + 4], "little")
                pos += 4
                if acc_ref == 0:
                    acc1 = (_rotl32((acc1 + word * prime2) & _MASK_32, 13) * prime1) & _MASK_32
                elif acc_ref == 1:
                    acc2 = (_rotl32((acc2 + word * prime2) & _MASK_32, 13) * prime1) & _MASK_32
                elif acc_ref == 2:
                    acc3 = (_rotl32((acc3 + word * prime2) & _MASK_32, 13) * prime1) & _MASK_32
                else:
                    acc4 = (_rotl32((acc4 + word * prime2) & _MASK_32, 13) * prime1) & _MASK_32
        digest = (_rotl32(acc1, 1) + _rotl32(acc2, 7) + _rotl32(acc3, 12) + _rotl32(acc4, 18)) & _MASK_32
    else:
        digest = (seed + prime5) & _MASK_32

    digest = (digest + length) & _MASK_32
    while pos + 4 <= length:
        word = int.from_bytes(buf[pos : pos + 4], "little")
        pos += 4
        digest = (_rotl32((digest + word * prime3) & _MASK_32, 17) * prime4) & _MASK_32
    while pos < length:
        digest = (_rotl32((digest + buf[pos] * prime5) & _MASK_32, 11) * prime1) & _MASK_32
        pos += 1

    digest ^= digest >> 15
    digest = (digest * prime2) & _MASK_32
    digest ^= digest >> 13
    digest = (digest * prime3) & _MASK_32
    digest ^= digest >> 16
    return digest & _MASK_32
