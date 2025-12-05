import random
import time

from ..config import CryptoConfig

__all__ = ["RandomGenerator"]


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
