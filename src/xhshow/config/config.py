import json
import warnings
from dataclasses import dataclass, field, replace
from typing import Any

__all__ = ["CryptoConfig"]


@dataclass(frozen=True)
class CryptoConfig:
    """Configuration constants for cryptographic operations"""

    # Bitwise operation constants
    MAX_32BIT: int = 0xFFFFFFFF
    MAX_SIGNED_32BIT: int = 0x7FFFFFFF

    # Base64 encoding constants
    STANDARD_BASE64_ALPHABET: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    CUSTOM_BASE64_ALPHABET: str = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
    X3_BASE64_ALPHABET: str = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"

    # XOR key for payload transformation (124 bytes)
    HEX_KEY: str = "71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a51a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277"  # noqa: E501

    # Hexadecimal processing constants
    EXPECTED_HEX_LENGTH: int = 32
    OUTPUT_BYTE_COUNT: int = 8
    HEX_CHUNK_SIZE: int = 2

    # Payload construction constants (default to 0 for public release)
    VERSION_BYTES: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    ENV_FINGERPRINT_A: list[int] = field(default_factory=lambda: [0, 0, 0, 0, 0, 0, 0, 0])
    ENV_FINGERPRINT_B: list[int] = field(default_factory=lambda: [0, 0, 0, 0, 0, 0, 0, 0])
    SEQUENCE_VALUE: int = 0
    WINDOW_PROPS_LENGTH: int = 0
    CHECKSUM_BASE: list[int] = field(default_factory=lambda: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    # Signature data template
    SIGNATURE_DATA_TEMPLATE: dict[str, str] = field(default_factory=lambda: {
        "x0": "4.2.6",
        "x1": "xhs-pc-web",
        "x2": "Windows",
        "x3": "",
        "x4": "",
    })

    # Prefix constants
    X3_PREFIX: str = "mns0301_"
    XYS_PREFIX: str = "XYS_"

    def with_overrides(self, **kwargs: Any) -> 'CryptoConfig':
        """
        Create a new config instance with overridden values

        Args:
            **kwargs: Field names and their new values

        Returns:
            CryptoConfig: New config instance with updated values

        Examples:
            >>> config = CryptoConfig().with_overrides(
            ...     SEQUENCE_VALUE=20,
            ...     XYS_PREFIX="CUSTOM_"
            ... )
        """
        return replace(self, **kwargs)

    @classmethod
    def from_xs_signature(cls, xs_signature: str) -> 'CryptoConfig':
        """
        [EXPERIMENTAL] Extract fingerprint config from existing XS signature

        WARNING: This is a temporary experimental feature for research purposes.
        It will be REMOVED in future versions once fingerprint generation is solved.

        Args:
            xs_signature: XYS_ or mns0301_ prefixed signature

        Returns:
            CryptoConfig: New config with extracted fingerprint values

        Examples:
            >>> config = CryptoConfig.from_xs_signature("XYS_...")
            >>> from xhshow import Xhshow
            >>> client = Xhshow(config=config)

        Raises:
            ValueError: Invalid signature format
        """
        warnings.warn(
            "from_xs_signature() is an EXPERIMENTAL feature for research only. "
            "It will be removed in future versions. "
            "Do NOT rely on this in production code.",
            FutureWarning,
            stacklevel=2
        )

        # TODO: Remove this method after fingerprint generation is solved
        # Issue: Research fingerprint generation algorithm

        extracted_params = cls._extract_fingerprint_params(xs_signature)
        return cls().with_overrides(**extracted_params)

    @classmethod
    def _extract_fingerprint_params(cls, xs_signature: str) -> dict[str, Any]:
        """
        Extract fingerprint parameters from XS signature

        Process:
        1. Remove outer prefix (XYS_ or mns0301_)
        2. Decode outer base64 (if XYS_)
        3. Extract x3 field from JSON (if XYS_)
        4. Remove x3 prefix (mns0301_)
        5. Decode x3 base64 to get 124-byte payload
        6. XOR decrypt with HEX_KEY
        7. Extract fingerprint data from fixed byte positions
        """
        # Step 1: Determine signature type and extract x3
        if xs_signature.startswith(cls.XYS_PREFIX):
            # Remove XYS_ prefix
            encoded_data = xs_signature[len(cls.XYS_PREFIX):]

            # Decode outer base64 using custom alphabet
            decoded_json = cls._decode_custom_base64_to_string(
                encoded_data, cls.CUSTOM_BASE64_ALPHABET, cls.STANDARD_BASE64_ALPHABET
            )

            # Parse JSON and extract x3
            try:
                data = json.loads(decoded_json)
                x3_signature = data.get("x3", "")
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse XS signature JSON: {e}") from e

        elif xs_signature.startswith(cls.X3_PREFIX):
            # Already an x3 signature
            x3_signature = xs_signature
        else:
            raise ValueError(
                f"Invalid signature format. Must start with '{cls.XYS_PREFIX}' or '{cls.X3_PREFIX}'"
            )

        # Step 2: Remove x3 prefix
        if not x3_signature.startswith(cls.X3_PREFIX):
            raise ValueError(f"x3 signature must start with '{cls.X3_PREFIX}'")

        x3_encoded = x3_signature[len(cls.X3_PREFIX):]

        # Step 3: Decode x3 base64 using X3 alphabet (returns bytes)
        payload_encrypted = cls._decode_custom_base64_to_bytes(
            x3_encoded, cls.X3_BASE64_ALPHABET, cls.STANDARD_BASE64_ALPHABET
        )

        # Step 4: XOR decrypt with HEX_KEY
        payload_bytes = cls._xor_decrypt(payload_encrypted, cls.HEX_KEY)

        # Step 5: Extract fingerprint data from fixed positions
        if len(payload_bytes) < 124:
            raise ValueError(f"Payload too short: expected 124 bytes, got {len(payload_bytes)}")

        # Get seed_byte_0 for XOR reversal
        seed_byte_0 = payload_bytes[4]

        # Extract checksum and reverse the XOR on first byte
        checksum_raw = list(payload_bytes[109:124])
        checksum_raw[0] = checksum_raw[0] ^ seed_byte_0

        return {
            "VERSION_BYTES": list(payload_bytes[0:4]),
            "ENV_FINGERPRINT_A": list(payload_bytes[8:16]),
            "ENV_FINGERPRINT_B": list(payload_bytes[16:24]),
            "SEQUENCE_VALUE": int.from_bytes(payload_bytes[24:28], byteorder='little'),
            "WINDOW_PROPS_LENGTH": int.from_bytes(payload_bytes[28:32], byteorder='little'),
            "CHECKSUM_BASE": checksum_raw,
        }

    @staticmethod
    def _decode_custom_base64_to_string(encoded: str, custom_alphabet: str, standard_alphabet: str) -> str:
        """Decode base64 string using custom alphabet to UTF-8 string"""
        import base64

        # Translate from custom alphabet to standard alphabet
        translation_table = str.maketrans(custom_alphabet, standard_alphabet)
        standard_encoded = encoded.translate(translation_table)

        # Decode using standard base64
        decoded_bytes = base64.b64decode(standard_encoded)
        return decoded_bytes.decode('utf-8')

    @staticmethod
    def _decode_custom_base64_to_bytes(encoded: str, custom_alphabet: str, standard_alphabet: str) -> bytes:
        """Decode base64 string using custom alphabet to raw bytes"""
        import base64

        # Translate from custom alphabet to standard alphabet
        translation_table = str.maketrans(custom_alphabet, standard_alphabet)
        standard_encoded = encoded.translate(translation_table)

        # Decode using standard base64
        return base64.b64decode(standard_encoded)

    @staticmethod
    def _xor_decrypt(encrypted_bytes: bytes, hex_key: str) -> bytes:
        """XOR decrypt payload using HEX_KEY"""
        key_bytes = bytes.fromhex(hex_key)
        decrypted = bytearray(len(encrypted_bytes))

        for i in range(len(encrypted_bytes)):
            if i < len(key_bytes):
                decrypted[i] = encrypted_bytes[i] ^ key_bytes[i]
            else:
                decrypted[i] = encrypted_bytes[i]

        return bytes(decrypted)
