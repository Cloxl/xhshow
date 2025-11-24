import time

from ..config import CryptoConfig
from ..utils.bit_ops import BitOperations
from ..utils.encoder import Base64Encoder
from ..utils.hex_utils import HexProcessor
from ..utils.random_gen import RandomGenerator

__all__ = ["CryptoProcessor"]


class CryptoProcessor:
    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()
        self.bit_ops = BitOperations(self.config)
        self.b64encoder = Base64Encoder(self.config)
        self.hex_processor = HexProcessor(self.config)
        self.random_gen = RandomGenerator()

    def _encode_timestamp(
        self, ts: int, randomize_first: bool = True
    ) -> list[int]:
        """
        Encode 8-byte timestamp in little-endian, XOR with 41,
        first byte can be randomized
        """
        key = [self.config.TIMESTAMP_XOR_KEY] * 8
        arr = self._int_to_le_bytes(ts, 8)
        encoded = [a ^ key[i] for i, a in enumerate(arr)]
        if randomize_first:
            encoded[0] = self.random_gen.generate_random_byte_in_range(0, 255)
        return encoded

    def _int_to_le_bytes(self, val: int, length: int = 4) -> list[int]:
        """Convert integer to little-endian byte array"""
        arr = []
        for _ in range(length):
            arr.append(val & 0xFF)
            val >>= 8
        return arr

    def _str_to_len_prefixed_bytes(self, s: str) -> list[int]:
        """Convert UTF-8 string to byte array with 1-byte length prefix"""
        buf = s.encode("utf-8")
        return [len(buf)] + list(buf)

    def _build_environment_bytes(self) -> list[int]:
        """Build environment byte array"""
        return (
            [self.config.ENV_STATIC_BYTES[0]]
            + [self.random_gen.generate_random_byte_in_range(10, 254)]
            + self.config.ENV_STATIC_BYTES[1:]
        )

    def build_payload_array(
        self,
        hex_parameter: str,
        a1_value: str,
        app_identifier: str = "xhs-pc-web",
        string_param: str = "",
    ) -> list[int]:
        """
        Build payload array

        Args:
            hex_parameter (str): 32-character hexadecimal parameter
            a1_value (str): a1 value from cookies
            app_identifier (str): Application identifier, default "xhs-pc-web"
            string_param (str): String parameter

        Returns:
            list[int]: Complete payload byte array
        """
        rand_num = self.random_gen.generate_random_int()
        ts = int(time.time() * 1000)
        startup_ts = ts - (
            self.config.STARTUP_TIME_OFFSET_MIN
            + self.random_gen.generate_random_byte_in_range(
                0,
                self.config.STARTUP_TIME_OFFSET_MAX
                - self.config.STARTUP_TIME_OFFSET_MIN,
            )
        )

        arr = []
        arr.extend(self.config.VERSION_BYTES)

        rand_bytes = self._int_to_le_bytes(rand_num, 4)
        arr.extend(rand_bytes)

        xor_key = rand_bytes[0]

        arr.extend(self._encode_timestamp(ts, True))
        arr.extend(self._int_to_le_bytes(startup_ts, 8))
        arr.extend(self._int_to_le_bytes(self.config.FIXED_INT_VALUE_1))
        arr.extend(self._int_to_le_bytes(self.config.FIXED_INT_VALUE_2))

        string_param_length = len(string_param.encode("utf-8"))
        arr.extend(self._int_to_le_bytes(string_param_length))

        md5_bytes = bytes.fromhex(hex_parameter)
        xor_md5_bytes = [b ^ xor_key for b in md5_bytes]
        arr.extend(xor_md5_bytes[:8])

        arr.extend(self._str_to_len_prefixed_bytes(a1_value))
        arr.extend(self._str_to_len_prefixed_bytes(app_identifier))

        arr.extend(
            [
                self.config.ENV_STATIC_BYTES[0],
                self.random_gen.generate_random_byte_in_range(0, 255),
            ]
            + self.config.ENV_STATIC_BYTES[1:]
        )

        return arr
