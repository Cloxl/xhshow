"""Encoding related module"""

import base64
import binascii
from collections.abc import Iterable

from ..config import CryptoConfig

__all__ = ["Base64Encoder"]


class Base64Encoder:
    def __init__(self, config: CryptoConfig):
        self.config = config

    def encode_to_b64(self, data_to_encode: str | bytes, alphabet: str = CryptoConfig.CUSTOM_BASE64_ALPHABET) -> str:
        """
        Encode a string using custom Base64 alphabet

        Args:
            data_to_encode: Original UTF-8 string to be encoded
            alphabet: Base64 alphabet to use for encoding

        Returns:
            Base64 string encoded using custom alphabet
        """
        if isinstance(data_to_encode, str):
            b = data_to_encode.encode("utf-8")
        elif isinstance(data_to_encode, bytes | bytearray | memoryview):
            b = bytes(data_to_encode)
        else:
            try:
                b = bytes(int(x) & 0xFF for x in data_to_encode)  # type: ignore[arg-type]
            except TypeError as e:
                raise TypeError(f"unsupported type: {type(data_to_encode)} (expected bytes/str/Iterable[int])") from e

        n = len(b)
        rem = n % 3
        stop = n - rem
        out_parts: list[str] = []

        CHUNK = 16383
        for i in range(0, stop, CHUNK):
            end = min(i + CHUNK, stop)
            j = i
            chunk_out: list[str] = []
            while j < end:
                val = (b[j] << 16) | (b[j + 1] << 8) | b[j + 2]
                chunk_out.append(
                    alphabet[(val >> 18) & 63]
                    + alphabet[(val >> 12) & 63]
                    + alphabet[(val >> 6) & 63]
                    + alphabet[val & 63]
                )
                j += 3
            out_parts.append("".join(chunk_out))

        if rem == 1:
            e = b[-1]
            out_parts.append(alphabet[e >> 2] + alphabet[(e << 4) & 63] + "==")
        elif rem == 2:
            e = (b[-2] << 8) | b[-1]
            out_parts.append(alphabet[(e >> 10) & 63] + alphabet[(e >> 4) & 63] + alphabet[(e << 2) & 63] + "=")

        return "".join(out_parts)

    def encode(self, data_to_encode: str) -> str:
        """
        Encode a string using custom Base64 alphabet (compatibility method)

        Args:
            data_to_encode: Original UTF-8 string to be encoded

        Returns:
            Base64 string encoded using custom alphabet
        """
        return self.encode_to_b64(data_to_encode, self.config.CUSTOM_BASE64_ALPHABET)

    @staticmethod
    def custom_to_b64(data: bytes | str | Iterable[int]) -> str:
        """
        XHS official encrypt method (tripletToBase64). same as above function, but FP gen must be deal binary string
        support:
          - str: use UTF-8 encode to byte
          - bytes/bytearray/memory view: use it straight
          - Iterable[int] (eg: list[int]): bitwise with & 0xFF trans to single bit

        Returns:
            Base64 string encoded using custom alphabet
        """
        alphabet = CryptoConfig.CUSTOM_BASE64_ALPHABET

        # —— all datas convert to bytes —— #
        if isinstance(data, str):
            b = data.encode("utf-8")
        elif isinstance(data, bytes | bytearray | memoryview):
            b = bytes(data)
        else:
            try:
                # allow list/tuple/any could be iterable int, auto & 0xFF  auto filter the value not between 0..255
                b = bytes(int(x) & 0xFF for x in data)  # type: ignore[arg-type]
            except TypeError as e:
                raise TypeError(f"unsupported type: {type(data)} (expected bytes/str/Iterable[int])") from e

        n = len(b)
        rem = n % 3
        stop = n - rem
        out_parts: list[str] = []

        CHUNK = 16383
        for i in range(0, stop, CHUNK):
            end = min(i + CHUNK, stop)
            j = i
            chunk_out: list[str] = []
            while j < end:
                val = (b[j] << 16) | (b[j + 1] << 8) | b[j + 2]
                chunk_out.append(
                    alphabet[(val >> 18) & 63]
                    + alphabet[(val >> 12) & 63]
                    + alphabet[(val >> 6) & 63]
                    + alphabet[val & 63]
                )
                j += 3
            out_parts.append("".join(chunk_out))

        if rem == 1:
            e = b[-1]
            out_parts.append(alphabet[e >> 2] + alphabet[(e << 4) & 63] + "==")
        elif rem == 2:
            e = (b[-2] << 8) | b[-1]
            out_parts.append(alphabet[(e >> 10) & 63] + alphabet[(e >> 4) & 63] + alphabet[(e << 2) & 63] + "=")

        return "".join(out_parts)

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
        reverse_translation_table = str.maketrans(
            self.config.CUSTOM_BASE64_ALPHABET, self.config.STANDARD_BASE64_ALPHABET
        )

        standard_encoded_string = encoded_string.translate(reverse_translation_table)
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
        reverse_translation_table = str.maketrans(self.config.X3_BASE64_ALPHABET, self.config.STANDARD_BASE64_ALPHABET)

        standard_encoded_string = encoded_string.translate(reverse_translation_table)
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

        translation_table = str.maketrans(self.config.STANDARD_BASE64_ALPHABET, self.config.X3_BASE64_ALPHABET)

        return standard_encoded_string.translate(translation_table)
