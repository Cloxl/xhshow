"""Bit operations and seed transformation module"""

from ..config import CryptoConfig

__all__ = ["BitOperations"]


class BitOperations:
    """Bit operations and seed transformation utility class"""

    def __init__(self, config: CryptoConfig):
        self.config = config

    def normalize_to_32bit(self, value: int) -> int:
        """
        Normalize value to 32-bit

        Args:
            value (int): Input value

        Returns:
            int: 32-bit normalized value
        """
        return value & self.config.MAX_32BIT

    def to_signed_32bit(self, unsigned_value: int) -> int:
        """
        Convert unsigned 32-bit value to signed 32-bit value

        Args:
            unsigned_value (int): Unsigned 32-bit value

        Returns:
            int: Signed 32-bit value
        """
        if unsigned_value > self.config.MAX_SIGNED_32BIT:
            return unsigned_value - 0x100000000
        return unsigned_value

    def compute_seed_value(self, seed_32bit: int) -> int:
        """
        Compute seed value transformation

        Args:
            seed_32bit (int): 32-bit seed value

        Returns:
            int: Transformed signed 32-bit integer
        """
        normalized_seed = self.normalize_to_32bit(seed_32bit)

        shift_15_bits = normalized_seed >> 15
        shift_13_bits = normalized_seed >> 13
        shift_12_bits = normalized_seed >> 12
        shift_10_bits = normalized_seed >> 10

        xor_masked_result = (shift_15_bits & ~shift_13_bits) | (shift_13_bits & ~shift_15_bits)
        shifted_result = ((xor_masked_result ^ shift_12_bits ^ shift_10_bits) << 31) & self.config.MAX_32BIT

        return self.to_signed_32bit(shifted_result)

    def xor_transform_array(self, source_integers: list[int]) -> bytearray:
        """
        Perform XOR transformation on integer array

        Args:
            source_integers (list[int]): Source integer array

        Returns:
            bytearray: Transformed byte array
        """
        result_bytes = bytearray(len(source_integers))
        key_bytes = bytes.fromhex(self.config.HEX_KEY)
        key_length = len(key_bytes)

        for index in range(len(source_integers)):
            if index < key_length:
                result_bytes[index] = (source_integers[index] ^ key_bytes[index]) & 0xFF
            else:
                result_bytes[index] = source_integers[index] & 0xFF

        return result_bytes
