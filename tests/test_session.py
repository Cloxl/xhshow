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


def test_signing_with_session_post(mock_crypto_processor):
    """
    Verify that POST requests use session state when provided.
    """
    client = Xhshow()
    session = SessionManager()

    uri = "/api/sns/web/v1/login"
    cookies = {"a1": "test_a1", "web_session": "test_session"}
    payload = {"username": "test_user", "password": "test_pass"}

    # Perform POST signing with session
    client.sign_headers_post(uri=uri, cookies=cookies, payload=payload, session=session)

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


def test_signing_without_session_post(mock_crypto_processor):
    """
    Verify that POST requests fall back to stateless mode when no session is provided.
    """
    client = Xhshow()
    uri = "/api/sns/web/v1/login"
    cookies = {"a1": "test_a1", "web_session": "test_session"}
    payload = {"username": "test_user", "password": "test_pass"}

    # Perform POST signing without session
    client.sign_headers_post(uri=uri, cookies=cookies, payload=payload)

    # Assert that build_payload_array was called
    mock_crypto_processor.build_payload_array.assert_called_once()

    # Get the actual arguments passed to the mock
    _, kwargs = mock_crypto_processor.build_payload_array.call_args
    actual_state = kwargs.get("sign_state")

    # Verify that no state was passed
    assert actual_state is None


def test_session_state_evolution():
    """
    Verify that SessionManager state evolves correctly across multiple calls.
    """
    session = SessionManager()

    initial_sequence = session.sequence_value
    initial_window_props = session.window_props_length
    initial_timestamp = session.page_load_timestamp

    # Call get_current_state multiple times
    uri1 = "/api/test1"
    state1 = session.get_current_state(uri1)

    uri2 = "/api/test2"
    state2 = session.get_current_state(uri2)

    uri3 = "/api/test3"
    state3 = session.get_current_state(uri3)

    # Verify page_load_timestamp remains constant
    assert state1.page_load_timestamp == initial_timestamp
    assert state2.page_load_timestamp == initial_timestamp
    assert state3.page_load_timestamp == initial_timestamp

    # Verify sequence_value increases (0 or 1 per call)
    assert state1.sequence_value >= initial_sequence
    assert state2.sequence_value >= state1.sequence_value
    assert state3.sequence_value >= state2.sequence_value

    # Verify window_props_length increases (1-10 per call)
    assert state1.window_props_length > initial_window_props
    assert state2.window_props_length > state1.window_props_length
    assert state3.window_props_length > state2.window_props_length

    # Verify uri_length uses actual URI length
    assert state1.uri_length == len(uri1)
    assert state2.uri_length == len(uri2)
    assert state3.uri_length == len(uri3)


def test_session_uri_length_accuracy():
    """
    Verify that uri_length in SignState always matches actual URI length.
    """
    session = SessionManager()

    test_cases = [
        "/api/short",
        "/api/medium/path/to/resource",
        "/api/very/long/path/to/some/deeply/nested/resource/endpoint",
    ]

    for uri in test_cases:
        state = session.get_current_state(uri)
        assert state.uri_length == len(uri)


def test_sign_xs_get_with_session(mock_crypto_processor):
    """
    Verify sign_xs_get passes session state correctly.
    """
    client = Xhshow()
    session = SessionManager()

    uri = "/api/sns/web/v1/homefeed"
    params = {"page": "1", "limit": "20"}

    signature = client.sign_xs_get(uri=uri, a1_value="test_a1", params=params, session=session)

    # Verify signature was generated
    assert signature.startswith("XYS_")

    # Verify build_payload_array was called with sign_state
    _, kwargs = mock_crypto_processor.build_payload_array.call_args
    actual_state = kwargs.get("sign_state")

    assert actual_state is not None
    assert actual_state.uri_length == len(uri)


def test_sign_xs_post_with_session(mock_crypto_processor):
    """
    Verify sign_xs_post passes session state correctly.
    """
    client = Xhshow()
    session = SessionManager()

    uri = "/api/sns/web/v1/comment/post"
    payload = {"note_id": "12345", "content": "Great post!"}

    signature = client.sign_xs_post(uri=uri, a1_value="test_a1", payload=payload, session=session)

    # Verify signature was generated
    assert signature.startswith("XYS_")

    # Verify build_payload_array was called with sign_state
    _, kwargs = mock_crypto_processor.build_payload_array.call_args
    actual_state = kwargs.get("sign_state")

    assert actual_state is not None
    assert actual_state.uri_length == len(uri)
