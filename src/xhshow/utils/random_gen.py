import binascii
import hashlib
import math
import random
import time

from ..config import CryptoConfig

__all__ = ["RandomGenerator"]

_BASE36_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"
_A1_CHARSET = "abcdefghijklmnopqrstuvwxyz1234567890"


def _int_to_base36(value: int) -> str:
    if value == 0:
        return "0"
    result = ""
    while value:
        value, remainder = divmod(value, 36)
        result = _BASE36_CHARS[remainder] + result
    return result


class RandomGenerator:
    """Random number generator utility"""

    def __init__(self):
        self.config = CryptoConfig()

    def generate_random_bytes(self, byte_count: int) -> list[int]:
        """
        Generate random byte array

        Args:
            byte_count (int): Number of bytes to generate

        Returns:
            list[int]: Random byte array
        """
        return [random.randint(0, self.config.MAX_BYTE) for _ in range(byte_count)]

    def generate_random_byte_in_range(self, min_val: int, max_val: int) -> int:
        """
        Generate random integer in range

        Args:
            min_val (int): Minimum value
            max_val (int): Maximum value

        Returns:
            int: Random integer in specified range
        """
        return random.randint(min_val, max_val)

    def generate_random_int(self) -> int:
        """
        Generate 32-bit random integer

        Returns:
            int: Random 32-bit integer
        """
        return random.randint(0, self.config.MAX_32BIT)

    def generate_b3_trace_id(self) -> str:
        """
        Generate x-b3-traceid (16 random hex characters)

        Returns:
            str: 16-character hexadecimal trace ID
        """
        return "".join(random.choice(self.config.HEX_CHARS) for _ in range(self.config.B3_TRACE_ID_LENGTH))

    def generate_xray_trace_id(self, timestamp: int | None = None, seq: int | None = None) -> str:
        """
        Generate x-xray-traceid (32 characters: 16 timestamp+seq + 16 random)

        Args:
            timestamp: Unix timestamp in milliseconds (defaults to current time)
            seq: Sequence number 0 to 2^23-1 (defaults to random value)

        Returns:
            str: 32-character hexadecimal trace ID
        """
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        if seq is None:
            seq = random.randint(0, self.config.XRAY_TRACE_ID_SEQ_MAX)

        # First 16 chars: XHS xray parameter uses timestamp bit operations
        part1 = format(
            ((timestamp << self.config.XRAY_TRACE_ID_TIMESTAMP_SHIFT) | seq),
            f"0{self.config.XRAY_TRACE_ID_PART1_LENGTH}x",
        )
        # Last 16 chars: completely random, untraceable, can be simplified
        part2 = "".join(random.choice(self.config.HEX_CHARS) for _ in range(self.config.XRAY_TRACE_ID_PART2_LENGTH))

        return part1 + part2

    @staticmethod
    def generate_random_ascii(length: int, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
        return "".join(random.choice(charset) for _ in range(length))

    @staticmethod
    def generate_a1() -> str:
        """
        Generate a1 cookie value

        Returns:
            str: 52-character a1 value
        """
        ts_hex = hex(int(time.time() * 1000))[2:]
        random_str = "".join(random.choices(_A1_CHARSET, k=30))
        a_part = ts_hex + random_str + "5" + "0" + "000"
        crc = binascii.crc32(a_part.encode()) & 0xFFFFFFFF
        return (a_part + str(crc))[:52]

    @staticmethod
    def generate_web_id(a1: str) -> str:
        """
        Generate web_id from a1 cookie value

        Args:
            a1: a1 cookie value

        Returns:
            str: 32-character hex MD5 hash
        """
        return hashlib.md5(a1.encode()).hexdigest()

    def generate_search_id(self) -> str:
        """
        Generate search_id for search endpoints

        Returns:
            str: Base36 encoded string from (timestamp_ms << 64) + random
        """
        timestamp_ms = int(time.time() * 1000)
        random_part = math.ceil(0x7FFFFFFE * random.random())
        return _int_to_base36((timestamp_ms << 64) + random_part)

    def generate_search_request_id(self) -> str:
        """
        Generate search request_id for search endpoints

        Returns:
            str: Format "{random}-{timestamp_ms}"
        """
        timestamp_ms = int(time.time() * 1000)
        random_part = math.ceil(0x7FFFFFFE * random.random())
        return f"{random_part}-{timestamp_ms}"
