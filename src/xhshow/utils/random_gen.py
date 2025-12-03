import random

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
        return [random.randint(0, 255) for _ in range(byte_count)]

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
