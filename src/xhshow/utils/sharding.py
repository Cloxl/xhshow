import ctypes
import random

__all__ = ["get_sharding_key"]

_C1 = 0xCC9E2D51
_C2 = 0x1B873593


def _imul(a: int, b: int) -> int:
    return ctypes.c_int32((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)).value


def _rotl32(x: int, r: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def get_sharding_key(user_id: str | None = None) -> int:
    if user_id is None:
        return random.randint(10, 100)

    data = user_id.encode("utf-8")
    length = len(data)
    r = 151488

    for o in range(length // 4):
        i = 4 * o
        u = data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
        u = _imul(u, _C1)
        u = _rotl32(u, 15)
        u = _imul(u, _C2)
        r ^= u
        r = _rotl32(r, 13)
        r = ctypes.c_int32(_imul(r, 5) + 0xE6546B64).value

    s = 4 * (length // 4)
    c = 0
    rem = length % 4
    if rem >= 3:
        c ^= data[s + 2] << 16
    if rem >= 2:
        c ^= data[s + 1] << 8
    if rem >= 1:
        c ^= data[s]
        c = _imul(c, _C1)
        c = _rotl32(c, 15)
        c = _imul(c, _C2)
        r ^= c

    r ^= length
    r &= 0xFFFFFFFF
    r ^= r >> 16
    r = _imul(r, 0x85EBCA6B) & 0xFFFFFFFF
    r ^= r >> 13
    r = _imul(r, 0xC2B2AE35) & 0xFFFFFFFF
    r ^= r >> 16

    return (r % 100) + 1
