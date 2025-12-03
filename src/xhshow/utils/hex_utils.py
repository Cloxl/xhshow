"""Hexadecimal processing module"""

from ..config import CryptoConfig

__all__ = ["HexProcessor"]


class HexProcessor:
    """Hexadecimal data processing utility class"""

    def __init__(self, config: CryptoConfig):
        self.config = config

    def hex_string_to_bytes(self, hex_string: str) -> list[int]:
        """
        Convert hexadecimal string to byte array

        Args:
            hex_string (str): Hexadecimal string

        Returns:
            list[int]: Byte array
        """
        byte_values = []
        for i in range(0, len(hex_string), self.config.HEX_CHUNK_SIZE):
            hex_chunk = hex_string[i : i + self.config.HEX_CHUNK_SIZE]
            byte_values.append(int(hex_chunk, 16))
        return byte_values

    def process_hex_parameter(self, hex_string: str, xor_key: int) -> list[int]:
        """
        Process hexadecimal parameter

        Args:
            hex_string (str): 32-character hexadecimal string
            xor_key (int): XOR key

        Returns:
            list[int]: Processed 8-byte integer list

        Raises:
            ValueError: When hex_string length is not 32
        """
        if len(hex_string) != self.config.EXPECTED_HEX_LENGTH:
            raise ValueError(f"hex parameter must be {self.config.EXPECTED_HEX_LENGTH} characters")

        byte_values = self.hex_string_to_bytes(hex_string)
        return [byte_val ^ xor_key for byte_val in byte_values][: self.config.OUTPUT_BYTE_COUNT]
