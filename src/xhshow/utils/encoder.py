"""编码相关模块"""

import base64

from ..config import CryptoConfig

__all__ = ["Base58Encoder"]


class Base58Encoder:
    """Base58编码器"""

    def __init__(self, config: CryptoConfig):
        self.config = config

    def encode_to_b58(self, input_bytes: bytes | bytearray) -> str:
        """
        将字节数据编码为Base58字符串

        Args:
            input_bytes (bytes | bytearray): 输入字节数据

        Returns:
            str: Base58编码字符串
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
        将Base58字符串解码为字节数据

        Args:
            encoded_string (str): Base58编码字符串

        Returns:
            bytearray: 解码后的字节数据
        """
        leading_zeros = 0
        for char in encoded_string:
            if char == self.config.BASE58_ALPHABET[0]:
                leading_zeros += 1
            else:
                break

        number = 0
        for char in encoded_string:
            char_index = self.config.BASE58_ALPHABET.index(char)
            number = number * self.config.BASE58_BASE + char_index

        byte_array = self._number_to_bytes(number)
        return bytearray([0] * leading_zeros + byte_array)

    def _bytes_to_number(self, input_bytes: bytes | bytearray) -> int:
        """将字节数组转换为数字"""
        result = 0
        for byte_value in input_bytes:
            result = result * self.config.BYTE_SIZE + byte_value
        return result

    def _number_to_bytes(self, number: int) -> list[int]:
        """将数字转换为字节数组"""
        if number == 0:
            return []
        byte_array = []
        while number > 0:
            byte_array.insert(0, number % self.config.BYTE_SIZE)
            number //= self.config.BYTE_SIZE
        return byte_array

    def _count_leading_zeros(self, input_bytes: bytes | bytearray) -> int:
        """计算前导零的数量"""
        count = 0
        for byte_value in input_bytes:
            if byte_value == 0:
                count += 1
            else:
                break
        return count

    def _number_to_base58_chars(self, number: int) -> list[str]:
        """将数字转换为Base58字符数组"""
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
        使用自定义的Base64码表来编码一个字符串。

        Args:
            data_to_encode: 需要被编码的原始UTF-8字符串。

        Returns:
            一个使用自定义码表编码后的Base64字符串。
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
        使用自定义的Base64码表来解码字符串

        Args:
            encoded_string: 使用自定义码表编码的Base64字符串

        Returns:
            解码后的原始UTF-8字符串
        """
        reverse_translation_table = str.maketrans(
            self.config.CUSTOM_BASE64_ALPHABET, self.config.STANDARD_BASE64_ALPHABET
        )

        standard_encoded_string = encoded_string.translate(reverse_translation_table)
        decoded_bytes = base64.b64decode(standard_encoded_string)
        return decoded_bytes.decode("utf-8")
