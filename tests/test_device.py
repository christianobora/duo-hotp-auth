"""Tests for device activation and management."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import serialization

from duo_hotp_auth.device import DuoDevice, extract_activation_code
from duo_hotp_auth import storage


def test_extract_activation_code_raw():
    """Test extracting activation code from raw string."""
    code = "test123456789-YXBpLWV4YW1wbGUuZHVvc2VjdXJpdHkuY29t"  # fake: test123456789-api-example.duosecurity.com
    result = extract_activation_code(code)
    assert result == code


def test_extract_activation_code_from_url():
    """Test extracting activation code from Duo QR URL."""
    url = "https://api-xxxx.duosecurity.com/frame/qr?value=duo%3A%2F%2Ftest123456789-YXBpLWV4YW1wbGUuZHVvc2VjdXJpdHkuY29t"
    result = extract_activation_code(url)
    assert result == "test123456789-YXBpLWV4YW1wbGUuZHVvc2VjdXJpdHkuY29t"  # fake: test123456789-api-example.duosecurity.com


def test_extract_activation_code_missing_value():
    """Test that missing value parameter raises ValueError."""
    url = "https://api-xxxx.duosecurity.com/frame/qr?other=param"
    with pytest.raises(ValueError, match="missing 'value='"):
        extract_activation_code(url)


def test_device_save_and_load():
    """Test that device can be saved and loaded correctly."""
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        # Mock storage directory
        original_get_storage_dir = storage.get_storage_dir

        def mock_get_storage_dir():
            return Path(tmpdir)

        storage.get_storage_dir = mock_get_storage_dir

        try:
            # Create a device instance
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            device = DuoDevice(
                akey="test-akey",
                pkey="test-pkey",
                host="api-test.duosecurity.com",
                public_key=public_key,
                private_key=private_key,
                hotp_secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                hotp_counter=5,
                name="test-device",
            )

            # Save device
            device.save()

            # Load device
            loaded_device = DuoDevice.load(name="test-device")

            # Verify all fields
            assert loaded_device.akey == device.akey
            assert loaded_device.pkey == device.pkey
            assert loaded_device.host == device.host
            assert loaded_device.hotp_secret == device.hotp_secret
            assert loaded_device.hotp_counter == device.hotp_counter
            assert loaded_device.name == device.name

            # Verify keys are the same (by comparing DER encoding)
            device_pub_der = device.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            loaded_pub_der = loaded_device.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            assert device_pub_der == loaded_pub_der

        finally:
            storage.get_storage_dir = original_get_storage_dir


def test_device_next_code():
    """Test HOTP code generation."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    device = DuoDevice(
        akey="test-akey",
        pkey="test-pkey",
        host="api-test.duosecurity.com",
        public_key=public_key,
        private_key=private_key,
        hotp_secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        hotp_counter=0,
        name="test-device",
    )

    # Generate first code (should match RFC test vector)
    code = device.next_code(persist=False)
    assert code == "755224"

    # Generate second code
    code = device.next_code(persist=False)
    assert code == "287082"


def test_device_next_code_no_secret():
    """Test that next_code raises error when no HOTP secret is available."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    device = DuoDevice(
        akey="test-akey",
        pkey="test-pkey",
        host="api-test.duosecurity.com",
        public_key=public_key,
        private_key=private_key,
        hotp_secret=None,
        hotp_counter=0,
        name="test-device",
    )

    with pytest.raises(RuntimeError, match="No HOTP secret available"):
        device.next_code()


@patch("duo_hotp_auth.device.requests.post")
def test_device_activate_success(mock_post):
    """Test successful device activation."""
    # Mock activation response
    mock_response = Mock()
    mock_response.json.return_value = {
        "response": {
            "akey": "test-akey",
            "pkey": "test-pkey",
            "hotp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        }
    }
    mock_response.raise_for_status = Mock()
    mock_post.return_value = mock_response

    # Create temporary directory for storage
    with tempfile.TemporaryDirectory() as tmpdir:
        original_get_storage_dir = storage.get_storage_dir

        def mock_get_storage_dir():
            return Path(tmpdir)

        storage.get_storage_dir = mock_get_storage_dir

        try:
            # Test activation
            # Format: identifier-host_b64 (split on first dash)
            # host_b64 is base64 of "api-test.duosecurity.com"
            activation_code = "testidentifier-YXBpLXRlc3QuZHVvc2VjdXJpdHkuY29t"  # identifier: testidentifier, host: api-test.duosecurity.com

            device = DuoDevice.activate(activation_code, name="test-device")

            assert device.akey == "test-akey"
            assert device.pkey == "test-pkey"
            assert device.host == "api-test.duosecurity.com"
            assert device.hotp_secret == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            assert device.hotp_counter == 0

            # Verify request was made
            assert mock_post.called
            url = mock_post.call_args[0][0]
            assert "api-test.duosecurity.com" in url
            assert "/push/v2/activation/testidentifier" in url

        finally:
            storage.get_storage_dir = original_get_storage_dir


def test_device_load_not_found():
    """Test that loading non-existent device raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="not found"):
        DuoDevice.load(name="non-existent-device")

