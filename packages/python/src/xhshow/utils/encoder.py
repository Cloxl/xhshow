"""Encoding related module"""

import base64
import binascii
from collections.abc import Iterable

from ..config import CryptoConfig

__all__ = ["Base64Encoder"]


class Base64Encoder:
    def __init__(self, config: CryptoConfig):
        self.config = config
        # Cache translation tables for better performance
        self._custom_encode_table = str.maketrans(
            config.STANDARD_BASE64_ALPHABET,
            config.CUSTOM_BASE64_ALPHABET,
        )
        self._custom_decode_table = str.maketrans(
            config.CUSTOM_BASE64_ALPHABET,
            config.STANDARD_BASE64_ALPHABET,
        )
        self._x3_encode_table = str.maketrans(
            config.STANDARD_BASE64_ALPHABET,
            config.X3_BASE64_ALPHABET,
        )
        self._x3_decode_table = str.maketrans(
            config.X3_BASE64_ALPHABET,
            config.STANDARD_BASE64_ALPHABET,
        )

    def encode(self, data_to_encode: bytes | str | Iterable[int]) -> str:
        """
        Encode a string using custom Base64 alphabet

        Args:
            data_to_encode: Original UTF-8 string to be encoded

        Returns:
            Base64 string encoded using custom alphabet
        """
        if isinstance(data_to_encode, bytes | bytearray):
            data_bytes = data_to_encode
        elif isinstance(data_to_encode, str):
            data_bytes = data_to_encode.encode("utf-8")
        else:
            # Iterable[int] case
            data_bytes = bytearray(data_to_encode)
        standard_encoded_bytes = base64.b64encode(data_bytes)
        standard_encoded_string = standard_encoded_bytes.decode("utf-8")

        return standard_encoded_string.translate(self._custom_encode_table)

    def decode(self, encoded_string: str) -> str:
        """
        Decode string using custom Base64 alphabet

        Args:
            encoded_string: Base64 string encoded with custom alphabet

        Returns:
            Decoded original UTF-8 string

        Raises:
            ValueError: Base64 decoding failed
        """
        standard_encoded_string = encoded_string.translate(self._custom_decode_table)

        try:
            decoded_bytes = base64.b64decode(standard_encoded_string)
        except (binascii.Error, ValueError) as e:
            raise ValueError("Invalid Base64 input: unable to decode string") from e
        return decoded_bytes.decode("utf-8")

    def decode_x3(self, encoded_string: str) -> bytes:
        """
        Decode x3 signature using X3_BASE64_ALPHABET

        Args:
            encoded_string: Base64 string encoded with X3 custom alphabet

        Returns:
            Decoded bytes

        Raises:
            ValueError: Base64 decoding failed
        """
        standard_encoded_string = encoded_string.translate(self._x3_decode_table)

        try:
            decoded_bytes = base64.b64decode(standard_encoded_string)
        except (binascii.Error, ValueError) as e:
            raise ValueError("Invalid Base64 input: unable to decode string") from e
        return decoded_bytes

    def encode_x3(self, input_bytes: bytes | bytearray) -> str:
        """
        Encode x3 signature using X3_BASE64_ALPHABET

        Args:
            input_bytes: Input byte data

        Returns:
            str: Base64 encoded string with X3 custom alphabet
        """
        standard_encoded_bytes = base64.b64encode(input_bytes)
        standard_encoded_string = standard_encoded_bytes.decode("utf-8")

        return standard_encoded_string.translate(self._x3_encode_table)
