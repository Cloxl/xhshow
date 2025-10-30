"""Encoding related module"""

import base64
import binascii

from ..config import CryptoConfig

__all__ = ["Base58Encoder"]


class Base58Encoder:
    """Base58 encoder"""

    def __init__(self, config: CryptoConfig):
        self.config = config

    def encode_to_b58(self, input_bytes: bytes | bytearray) -> str:
        """
        Encode byte data to Base58 string

        Args:
            input_bytes (bytes | bytearray): Input byte data

        Returns:
            str: Base58 encoded string
        """
        number_accumulator = self._bytes_to_number(input_bytes)
        leading_zeros_count = self._count_leading_zeros(input_bytes)
        encoded_characters = self._number_to_base58_chars(number_accumulator)

        encoded_characters.extend(
            [self.config.BASE58_ALPHABET[0]] * leading_zeros_count
        )
        return "".join(reversed(encoded_characters))

    def decode_from_b58(self, encoded_string: str) -> bytearray:
        """
        Decode Base58 string to byte data

        Args:
            encoded_string (str): Base58 encoded string

        Returns:
            bytearray: Decoded byte data

        Raises:
            ValueError: Invalid Base58 character
        """
        leading_zeros = 0
        for char in encoded_string:
            if char == self.config.BASE58_ALPHABET[0]:
                leading_zeros += 1
            else:
                break

        number = 0
        for char in encoded_string:
            try:
                char_index = self.config.BASE58_ALPHABET.index(char)
            except ValueError:
                raise ValueError(
                    f"Invalid Base58 character: '{char}' not in alphabet"
                ) from None
            number = number * self.config.BASE58_BASE + char_index

        byte_array = self._number_to_bytes(number)
        return bytearray([0] * leading_zeros + byte_array)

    def _bytes_to_number(self, input_bytes: bytes | bytearray) -> int:
        """Convert byte array to number"""
        result = 0
        for byte_value in input_bytes:
            result = result * self.config.BYTE_SIZE + byte_value
        return result

    def _number_to_bytes(self, number: int) -> list[int]:
        """Convert number to byte array"""
        if number == 0:
            return []
        byte_array = []
        while number > 0:
            byte_array.insert(0, number % self.config.BYTE_SIZE)
            number //= self.config.BYTE_SIZE
        return byte_array

    def _count_leading_zeros(self, input_bytes: bytes | bytearray) -> int:
        """Count leading zeros"""
        count = 0
        for byte_value in input_bytes:
            if byte_value == 0:
                count += 1
            else:
                break
        return count

    def _number_to_base58_chars(self, number: int) -> list[str]:
        """Convert number to Base58 character array"""
        characters = []
        while number > 0:
            number, remainder = divmod(number, self.config.BASE58_BASE)
            characters.append(self.config.BASE58_ALPHABET[remainder])
        return characters


class Base64Encoder:
    def __init__(self, config: CryptoConfig):
        self.config = config

    def encode_to_b64(self, data_to_encode: str) -> str:
        """
        Encode a string using custom Base64 alphabet

        Args:
            data_to_encode: Original UTF-8 string to be encoded

        Returns:
            Base64 string encoded using custom alphabet
        """
        data_bytes = data_to_encode.encode("utf-8")
        standard_encoded_bytes = base64.b64encode(data_bytes)
        standard_encoded_string = standard_encoded_bytes.decode("utf-8")

        translation_table = str.maketrans(
            self.config.STANDARD_BASE64_ALPHABET, self.config.CUSTOM_BASE64_ALPHABET
        )

        return standard_encoded_string.translate(translation_table)

    def decode_from_b64(self, encoded_string: str) -> str:
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
