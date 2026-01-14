import random
import time
from typing import NamedTuple


class SignState(NamedTuple):
    """Immutable state for a single signing operation."""

    page_load_timestamp: int
    sequence_value: int
    window_props_length: int
    uri_length: int


class SessionManager:
    """
    Manages the state for a simulated user session to generate more realistic signatures.

    This class maintains counters that should persist and evolve across multiple requests
    within the same logical session.
    """

    def __init__(self):
        self.page_load_timestamp: int = int(time.time() * 1000)
        self.sequence_value: int = random.randint(15, 17)
        self.window_props_length: int = random.randint(1000, 2000)
        self.uri_length: int = random.randint(200, 400)

    def update_state(self):
        """
        Updates the session state to simulate user activity between requests.

        This method should be called before each signing operation.
        """
        # Simulate realistic counter increments
        # self.sequence_value += random.randint(0, 1)
        self.window_props_length += random.randint(1, 10)
        self.uri_length += random.randint(0, 2)

    def get_current_state(self, uri: str) -> SignState:
        """
        Get the current signing state, with the option to use real URI length.

        For maximum realism, the actual URI length is used, but the internal
        counter is still maintained for other purposes.

        Args:
            uri (str): The URI string for the current request.

        Returns:
            SignState: An immutable tuple with the current state for signing.
        """
        self.update_state()
        return SignState(
            page_load_timestamp=self.page_load_timestamp,
            sequence_value=self.sequence_value,
            window_props_length=self.window_props_length,
            uri_length=len(uri),  # Use the real URI length for the signature
        )
