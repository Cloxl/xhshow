"""
Custom CRC32 helper wrapped in a class.

Main entry:
    CRC32.crc32_js_int(data)

This implements a JavaScript-style CRC32 variant compatible with:

    (-1 ^ c ^ 0xEDB88320) >>> 0

where `c` is the intermediate CRC state produced by the core CRC32 loop.
"""

from __future__ import annotations

from collections.abc import Iterable

DataLike = str | bytes | bytearray | memoryview | Iterable[int]
__all__ = ["CRC32"]


class CRC32:
    """CRC32 calculator with a JS-compatible static entry."""

    MASK32: int = 0xFFFFFFFF
    POLY: int = 0xEDB88320
    _TABLE: list[int] | None = None

    @classmethod
    def _ensure_table(cls) -> None:
        """Lazy-init CRC32 lookup table once."""
        if cls._TABLE is not None:
            return

        tbl = [0] * 256
        for d in range(256):
            r = d
            for _ in range(8):
                r = ((r >> 1) ^ cls.POLY) if (r & 1) else (r >> 1)
                r &= cls.MASK32
            tbl[d] = r
        cls._TABLE = tbl

    @classmethod
    def _crc32_core(cls, data: DataLike, *, string_mode: str = "js") -> int:
        """
        Core CRC32 state update (no final NOT/XOR).

        Args:
            data:
                - str: interpreted depending on ``string_mode``:
                    * "js": lower 8 bits of ord(char) (JS charCodeAt behavior)
                    * "utf8": UTF-8 encode string to bytes first
                - bytes / bytearray / memoryview: used as-is
                - Iterable[int]: each value will be ``& 0xFF`` and treated as a byte
            string_mode: How to handle string input ("js" or "utf8").

        Returns:
            Intermediate CRC state `c` (before final bitwise NOT / XOR).
        """
        cls._ensure_table()
        assert cls._TABLE is not None  # for type checkers

        c = cls.MASK32

        if isinstance(data, bytes | bytearray | memoryview):
            it = bytes(data)
        elif isinstance(data, str):
            if string_mode.lower() == "utf8":
                it = data.encode("utf-8")
            else:  # "js" mode: charCodeAt & 0xFF
                it = (ord(ch) & 0xFF for ch in data)
        else:
            it = ((int(b) & 0xFF) for b in data)

        for b in it:
            c = (cls._TABLE[((c & 0xFF) ^ b) & 0xFF] ^ (c >> 8)) & cls.MASK32

        return c

    @staticmethod
    def _to_signed32(u: int) -> int:
        """
        Convert an unsigned 32-bit int to signed 32-bit representation.

        Args:
            u: Unsigned 32-bit integer (0..0xFFFFFFFF).

        Returns:
            Signed 32-bit integer in range [-2^31, 2^31-1].
        """
        return u - 0x100000000 if (u & 0x80000000) else u

    @classmethod
    def crc32_js_int(
        cls,
        data: DataLike,
        *,
        string_mode: str = "js",
        signed: bool = True,
    ) -> int:
        """
        JavaScript-style CRC32 public entry.

        This matches the JS expression:

            (-1 ^ c ^ 0xEDB88320) >>> 0

        where `c` is the intermediate CRC state from `_crc32_core`.

        Args:
            data: Input data (str/bytes/iterable of ints).
            string_mode: How to treat string input ("js" or "utf8").
            signed:
                If True, return signed 32-bit integer;
                If False, return unsigned 32-bit integer (0..0xFFFFFFFF).

        Returns:
            CRC32 value as 32-bit integer (signed or unsigned).
        """
        c = cls._crc32_core(data, string_mode=string_mode)
        a = cls.POLY
        u = ((cls.MASK32 ^ c) ^ a) & cls.MASK32  # (-1 ^ c ^ a) >>> 0
        return cls._to_signed32(u) if signed else u
