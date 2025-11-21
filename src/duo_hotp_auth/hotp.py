"""RFC 4226 HOTP (HMAC-based One-Time Password) implementation."""

import base64
import hashlib
import hmac
from typing import Union


def generate_hotp(secret: Union[str, bytes], counter: int, digits: int = 6) -> str:
    """
    Generate an HOTP code using RFC 4226.

    Args:
        secret: The HOTP secret as a string (Base32 or Base64 encoded) or bytes.
        counter: The moving counter value (incremented after each use).
        digits: Number of digits in the output code (default: 6).

    Returns:
        A zero-padded HOTP code string.

    Raises:
        ValueError: If the secret cannot be decoded from Base32 or Base64.
    """
    # Decode secret if it's a string
    if isinstance(secret, str):
        raw_secret = _decode_secret(secret)
    else:
        raw_secret = secret

    # Convert counter to 8-byte big-endian integer
    counter_bytes = counter.to_bytes(8, byteorder="big")

    # Compute HMAC-SHA1
    hmac_digest = hmac.new(raw_secret, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation (RFC 4226, Section 5.4)
    offset = hmac_digest[19] & 0x0F
    binary = (
        ((hmac_digest[offset] & 0x7F) << 24)
        | ((hmac_digest[offset + 1] & 0xFF) << 16)
        | ((hmac_digest[offset + 2] & 0xFF) << 8)
        | (hmac_digest[offset + 3] & 0xFF)
    )

    # Generate code: binary % 10^digits, zero-padded
    code = binary % (10**digits)
    return f"{code:0{digits}d}"


def _decode_secret(secret: str) -> bytes:
    """
    Decode HOTP secret from Base32 (preferred) or Base64.

    Args:
        secret: The encoded secret string.

    Returns:
        Decoded secret as bytes.

    Raises:
        ValueError: If the secret cannot be decoded from either format.
    """
    secret = secret.strip()
    # Try Base32 first (common for OTP secrets)
    try:
        return base64.b32decode(secret, casefold=True)
    except Exception:
        pass

    # Fall back to Base64
    try:
        return base64.b64decode(secret)
    except Exception as e:
        raise ValueError(
            f"Unable to decode HOTP secret from Base32 or Base64: {e}"
        ) from e

