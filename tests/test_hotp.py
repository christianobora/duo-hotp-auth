"""Tests for HOTP generation."""

import pytest

from duo_hotp_auth.hotp import generate_hotp


# RFC 4226 test vectors (Appendix D)
# Secret: "12345678901234567890" (Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
RFC4226_TEST_VECTORS = [
    # (counter, expected_code)
    (0, "755224"),
    (1, "287082"),
    (2, "359152"),
    (3, "969429"),
    (4, "338314"),
    (5, "254676"),
    (6, "287922"),
    (7, "162583"),
    (8, "399871"),
    (9, "520489"),
]


def test_rfc4226_test_vectors():
    """Test HOTP generation against RFC 4226 test vectors."""
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # Base32 encoded "12345678901234567890"

    for counter, expected_code in RFC4226_TEST_VECTORS:
        code = generate_hotp(secret, counter, digits=6)
        assert code == expected_code, f"Counter {counter}: expected {expected_code}, got {code}"


def test_hotp_different_digits():
    """Test HOTP generation with different digit counts."""
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    code_6 = generate_hotp(secret, 0, digits=6)
    code_7 = generate_hotp(secret, 0, digits=7)
    code_8 = generate_hotp(secret, 0, digits=8)

    assert len(code_6) == 6
    assert len(code_7) == 7
    assert len(code_8) == 8

    # 6-digit code should be a suffix of 7-digit code
    assert code_7.endswith(code_6)


def test_hotp_base32_decoding():
    """Test that Base32 secrets are decoded correctly."""
    secret_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    code = generate_hotp(secret_base32, 0, digits=6)
    assert code == "755224"


def test_hotp_base64_decoding():
    """Test that Base64 secrets are decoded correctly."""
    # Base64 encoded "12345678901234567890"
    secret_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
    code = generate_hotp(secret_base64, 0, digits=6)
    # Should produce same result as Base32 version
    assert code == "755224"


def test_hotp_bytes_secret():
    """Test HOTP generation with bytes secret."""
    secret_bytes = b"12345678901234567890"
    code = generate_hotp(secret_bytes, 0, digits=6)
    assert code == "755224"


def test_hotp_invalid_secret():
    """Test that invalid secrets raise ValueError."""
    with pytest.raises(ValueError, match="Unable to decode"):
        generate_hotp("not-a-valid-secret", 0, digits=6)


def test_hotp_counter_increment():
    """Test that different counters produce different codes."""
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    code_0 = generate_hotp(secret, 0, digits=6)
    code_1 = generate_hotp(secret, 1, digits=6)
    code_2 = generate_hotp(secret, 2, digits=6)

    # Codes should be different
    assert code_0 != code_1
    assert code_1 != code_2
    assert code_0 != code_2

    # But should match RFC test vectors
    assert code_0 == "755224"
    assert code_1 == "287082"
    assert code_2 == "359152"

