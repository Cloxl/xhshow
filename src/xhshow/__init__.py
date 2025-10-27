import sys

if sys.version_info < (3, 10):
    print(
        f"Error: xhshow requires Python 3.10 or higher. "
        f"You are using Python "
        f"{sys.version_info.major}.{sys.version_info.minor}."
        f"{sys.version_info.micro}. "
        f"Please upgrade your Python installation."
    )
    sys.exit(1)

from .client import Xhshow
from .config import CryptoConfig
from .core.crypto import CryptoProcessor

__version__ = "0.1.0"
__all__ = ["CryptoConfig", "CryptoProcessor", "Xhshow"]
