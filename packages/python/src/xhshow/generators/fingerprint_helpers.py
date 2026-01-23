"""Fingerprint generation helper functions"""

import hashlib
import random
import secrets
from typing import Any

from ..data import fingerprint_data as FPData

__all__ = [
    "weighted_random_choice",
    "get_renderer_info",
    "get_screen_config",
    "generate_canvas_hash",
    "generate_webgl_hash",
]


def weighted_random_choice(options: list, weights: list) -> Any:
    """
    Random choice a value from list according to the given weights

    Args:
        options: Option list
        weights: Weight list mapping the option list (without normalization)

    Returns:
        Randomly chosen value from options
    """
    return f"{random.choices(options, weights=weights, k=1)[0]}"


def get_renderer_info() -> tuple[str, str]:
    """
    Get random GPU renderer information

    Returns:
        Tuple of (vendor, renderer)
    """
    renderer_str = random.choice(FPData.GPU_VENDORS)
    vendor, renderer = renderer_str.split("|")
    return vendor, renderer


def get_screen_config() -> dict[str, Any]:
    """
    Get random screen configuration with width, height, and available dimensions

    Returns:
        Dictionary containing screen configuration
    """
    width_str, height_str = weighted_random_choice(
        FPData.SCREEN_RESOLUTIONS["resolutions"],
        FPData.SCREEN_RESOLUTIONS["weights"],
    ).split(";")

    width = int(width_str)
    height = int(height_str)

    if random.choice([True, False]):
        avail_width = width - int(weighted_random_choice([0, 30, 60, 80], [0.1, 0.4, 0.3, 0.2]))
        avail_height = height
    else:
        avail_width = width
        avail_height = height - int(weighted_random_choice([30, 60, 80, 100], [0.2, 0.5, 0.2, 0.1]))

    return {
        "width": width,
        "height": height,
        "availWidth": avail_width,
        "availHeight": avail_height,
    }


def generate_canvas_hash() -> str:
    """
    Generate canvas fingerprint hash

    Returns:
        Canvas hash string
    """
    return FPData.CANVAS_HASH


def generate_webgl_hash() -> str:
    """
    Generate WebGL fingerprint hash

    Returns:
        WebGL hash (MD5 hex string)
    """
    return hashlib.md5(secrets.token_bytes(32)).hexdigest()
