from unittest.mock import MagicMock, patch

import pytest

from xhshow.client import Xhshow
from xhshow.session import SessionManager, SignState


@pytest.fixture
def mock_crypto_processor():
    """Fixture to mock the CryptoProcessor and its methods."""
    with patch("xhshow.client.CryptoProcessor") as mock_proc_class:
        mock_instance = mock_proc_class.return_value
        mock_instance.build_payload_array = MagicMock(return_value=[])
        mock_instance.bit_ops.xor_transform_array = MagicMock(return_value=b"")
        mock_instance.b64encoder.encode_x3 = MagicMock(return_value="encoded_x3")
        mock_instance.b64encoder.encode = MagicMock(return_value="encoded_xs")

        # Set up the config mock to return a real dictionary
        mock_instance.config.SIGNATURE_DATA_TEMPLATE = {
            "x0": "4.2.6",
            "x1": "xhs-pc-web",
            "x2": "Windows",
            "x3": "",
            "x4": "",
        }
        mock_instance.config.X3_PREFIX = "mns0301_"
        mock_instance.config.XYS_PREFIX = "XYS_"

        yield mock_instance


def test_signing_with_session(mock_crypto_processor):
    """
    Verify that when a session object is provided, its state is used for signing.
    """
    client = Xhshow()
    session = SessionManager()

    # Update state to ensure counters are not zero
    session.update_state()
    session.update_state()

    uri = "/api/sns/web/v1/user/posted"
    cookies = {"a1": "test_a1", "web_session": "test_session"}

    # Perform signing
    client.sign_headers_get(uri=uri, cookies=cookies, session=session)

    # Assert that build_payload_array was called
    mock_crypto_processor.build_payload_array.assert_called_once()

    # Get the actual arguments passed to the mock
    _, kwargs = mock_crypto_processor.build_payload_array.call_args
    actual_state = kwargs.get("sign_state")

    # Verify the state matches
    assert actual_state is not None
    assert isinstance(actual_state, SignState)
    assert actual_state.page_load_timestamp == session.page_load_timestamp
    assert actual_state.sequence_value == session.sequence_value
    assert actual_state.window_props_length == session.window_props_length
    assert actual_state.uri_length == len(uri)


def test_signing_without_session(mock_crypto_processor):
    """
    Verify that signing falls back to the old method when no session is provided.
    """
    client = Xhshow()
    uri = "/api/sns/web/v1/user/posted"
    cookies = {"a1": "test_a1", "web_session": "test_session"}

    # Perform signing without a session
    client.sign_headers_get(uri=uri, cookies=cookies)

    # Assert that build_payload_array was called
    mock_crypto_processor.build_payload_array.assert_called_once()

    # Get the actual arguments passed to the mock
    _, kwargs = mock_crypto_processor.build_payload_array.call_args
    actual_state = kwargs.get("sign_state")

    # Verify that no state was passed (it should be None)
    assert actual_state is None
