import hashlib
import struct
import time
from typing import TYPE_CHECKING

from ..config import CryptoConfig
from ..utils.bit_ops import BitOperations
from ..utils.encoder import Base64Encoder
from ..utils.hex_utils import HexProcessor
from ..utils.random_gen import RandomGenerator
from ..utils.url_utils import extract_api_path

if TYPE_CHECKING:
    from ..session import SignState


__all__ = ["CryptoProcessor"]


class CryptoProcessor:
    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()
        self.bit_ops = BitOperations(self.config)
        self.b64encoder = Base64Encoder(self.config)
        self.hex_processor = HexProcessor(self.config)
        self.random_gen = RandomGenerator()

    def _int_to_le_bytes(self, val: int, length: int = 4) -> list[int]:
        """Convert integer to little-endian byte array"""
        arr = []
        for _ in range(length):
            arr.append(val & 0xFF)
            val >>= 8
        return arr

    def _rotate_left(self, val: int, n: int) -> int:
        """32-bit left rotation"""
        return ((val << n) | (val >> (32 - n))) & self.config.MAX_32BIT

    def _custom_hash_v2(self, input_bytes: list[int]) -> list[int]:
        """
        Custom hash function for a3 field generation
        Input: byte list (must be multiple of 8)
        Output: 16-byte list
        """
        s0, s1, s2, s3 = self.config.HASH_IV
        length = len(input_bytes)

        s0 ^= length
        s1 ^= length << 8
        s2 ^= length << 16
        s3 ^= length << 24

        for i in range(length // 8):
            v0, v1 = struct.unpack("<II", bytes(input_bytes[i * 8 : (i + 1) * 8]))

            s0 = self._rotate_left(((s0 + v0) & self.config.MAX_32BIT) ^ s2, 7)
            s1 = self._rotate_left(((v0 ^ s1) + s3) & self.config.MAX_32BIT, 11)
            s2 = self._rotate_left(((s2 + v1) & self.config.MAX_32BIT) ^ s0, 13)
            s3 = self._rotate_left(((s3 ^ v1) + s1) & self.config.MAX_32BIT, 17)

        t0 = s0 ^ length
        t1 = s1 ^ t0
        t2 = (s2 + t1) & self.config.MAX_32BIT
        t3 = s3 ^ t2

        rot_t0 = self._rotate_left(t0, 9)
        rot_t1 = self._rotate_left(t1, 13)
        rot_t2 = self._rotate_left(t2, 17)
        rot_t3 = self._rotate_left(t3, 19)

        s0 = (rot_t0 + rot_t2) & self.config.MAX_32BIT
        s1 = rot_t1 ^ rot_t3
        s2 = (rot_t2 + s0) & self.config.MAX_32BIT
        s3 = rot_t3 ^ s1

        result = []
        for s in [s0, s1, s2, s3]:
            result.extend(self._int_to_le_bytes(s, 4))
        return result

    def build_payload_array(
        self,
        hex_parameter: str,
        a1_value: str,
        app_identifier: str = "xhs-pc-web",
        string_param: str = "",
        timestamp: float | None = None,
        sign_state: "SignState | None" = None,
    ) -> list[int]:
        """
        Build 144-byte payload array (mns0301 version)

        Args:
            hex_parameter (str): 32-character hexadecimal parameter (MD5 hash of uri+data)
            a1_value (str): a1 value from cookies
            app_identifier (str): Application identifier, default "xhs-pc-web"
            string_param (str): String parameter (URI+data for MD5 and length calculation)
            timestamp (float | None): Unix timestamp in seconds (defaults to current time)
            sign_state (SignState | None): Optional state for realistic signature generation.

        Returns:
            list[int]: Complete payload byte array (144 bytes)
        """
        timestamp = time.time() if timestamp is None else timestamp
        seed = self.random_gen.generate_random_int()
        seed_byte = seed & 0xFF

        payload = list(self.config.VERSION_BYTES)
        payload.extend(self._int_to_le_bytes(seed, 4))

        ts_bytes = self._int_to_le_bytes(int(timestamp * 1000), self.config.TIMESTAMP_LE_LENGTH)
        payload.extend(ts_bytes)

        if sign_state:
            payload.extend(self._int_to_le_bytes(sign_state.page_load_timestamp, self.config.TIMESTAMP_LE_LENGTH))
            payload.extend(self._int_to_le_bytes(sign_state.sequence_value, 4))
            payload.extend(self._int_to_le_bytes(sign_state.window_props_length, 4))
            payload.extend(self._int_to_le_bytes(sign_state.uri_length, 4))
        else:
            time_offset = self.random_gen.generate_random_byte_in_range(
                self.config.ENV_FINGERPRINT_TIME_OFFSET_MIN,
                self.config.ENV_FINGERPRINT_TIME_OFFSET_MAX,
            )
            effective_ts_ms = int((timestamp - time_offset) * 1000)
            payload.extend(self._int_to_le_bytes(effective_ts_ms, self.config.TIMESTAMP_LE_LENGTH))

            sequence_value = self.random_gen.generate_random_byte_in_range(
                self.config.SEQUENCE_VALUE_MIN, self.config.SEQUENCE_VALUE_MAX
            )
            payload.extend(self._int_to_le_bytes(sequence_value, 4))

            window_props_length = self.random_gen.generate_random_byte_in_range(
                self.config.WINDOW_PROPS_LENGTH_MIN, self.config.WINDOW_PROPS_LENGTH_MAX
            )
            payload.extend(self._int_to_le_bytes(window_props_length, 4))

            uri_length = len(string_param.encode("utf-8"))
            payload.extend(self._int_to_le_bytes(uri_length, 4))

        md5_bytes = bytes.fromhex(hex_parameter)
        payload.extend([md5_bytes[i] ^ seed_byte for i in range(self.config.MD5_XOR_LENGTH)])

        a1_bytes = a1_value.encode("utf-8")[: self.config.A1_LENGTH].ljust(self.config.A1_LENGTH, b"\x00")
        payload.append(len(a1_bytes))
        payload.extend(a1_bytes)

        app_bytes = app_identifier.encode("utf-8")[: self.config.APP_ID_LENGTH].ljust(
            self.config.APP_ID_LENGTH, b"\x00"
        )
        payload.append(len(app_bytes))
        payload.extend(app_bytes)

        part11 = [1, seed_byte ^ self.config.ENV_TABLE[0]]
        part11 += [self.config.ENV_TABLE[i] ^ self.config.ENV_CHECKS_DEFAULT[i] for i in range(1, 15)]
        payload.extend(part11)

        api_path = extract_api_path(string_param)
        api_path_bytes = api_path.encode("utf-8")
        hex_md5 = hashlib.md5(api_path_bytes).hexdigest()
        md5_path_bytes = [int(hex_md5[i : i + 2], 16) for i in range(0, 32, 2)]

        payload.extend(self.config.A3_PREFIX + [b ^ seed_byte for b in self._custom_hash_v2(ts_bytes + md5_path_bytes)])

        return payload
