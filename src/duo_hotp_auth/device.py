"""Duo device activation and management."""

import base64
from typing import Optional
from urllib.parse import parse_qs, unquote, urlencode, urlparse

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from duo_hotp_auth import storage
from duo_hotp_auth.hotp import generate_hotp


CHARSET = "utf-8"


def b64_fix(s: str) -> bytes:
    """Fix and decode Base64 string with padding."""
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def extract_activation_code(source: str) -> str:
    """
    Extract raw Duo activation code from either a QR URL or a raw string.

    Args:
        source: Either a full Duo QR URL or a raw activation code.

    Returns:
        Raw activation code string.

    Raises:
        ValueError: If the URL is missing the required 'value' parameter.
    """
    source = source.strip()

    # If it's not a URL, return as-is
    if not source.lower().startswith(("http://", "https://")):
        return source

    # Parse URL and extract value parameter
    parsed = urlparse(source)
    qs = parse_qs(parsed.query)
    raw_value = qs.get("value", [None])[0]
    if raw_value is None:
        raise ValueError("Activation URL missing 'value=' parameter")

    decoded = unquote(raw_value)

    # Strip duo:// prefix if present
    if decoded.startswith("duo://"):
        return decoded[6:]

    # Handle other protocol prefixes
    if "://" in decoded:
        return decoded.split("://", 1)[1]

    return decoded


class DuoDevice:
    """
    Represents an activated Duo Mobile device.

    This class handles device activation, persistence, and HOTP code generation.
    """

    def __init__(
        self,
        akey: str,
        pkey: str,
        host: str,
        public_key: rsa.RSAPublicKey,
        private_key: rsa.RSAPrivateKey,
        hotp_secret: Optional[str] = None,
        hotp_counter: int = 0,
        name: Optional[str] = None,
    ):
        """
        Initialize a DuoDevice instance.

        Args:
            akey: Activation key from Duo.
            pkey: Private key identifier from Duo.
            host: Duo API hostname.
            public_key: RSA public key object.
            private_key: RSA private key object.
            hotp_secret: Optional HOTP secret for code generation.
            hotp_counter: Current HOTP counter value.
            name: Device name for storage.
        """
        self.akey = akey
        self.pkey = pkey
        self.host = host
        self.public_key = public_key
        self.private_key = private_key
        self.hotp_secret = hotp_secret
        self.hotp_counter = hotp_counter
        self.name = name or "default"

    @classmethod
    def activate(
        cls, activation_code_or_url: str, name: Optional[str] = None
    ) -> "DuoDevice":
        """
        Activate a new Duo Mobile device from an activation code or QR URL.

        Args:
            activation_code_or_url: Either a raw activation code or a full Duo QR URL.
            name: Optional device name (default: "default").

        Returns:
            Activated DuoDevice instance.

        Raises:
            ValueError: If the activation code is invalid.
            requests.RequestException: If the activation request fails.
        """
        activation_code = extract_activation_code(activation_code_or_url)

        # Generate RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Prepare activation parameters
        params = {
            "customer_protocol": "1",
            "jailbroken": "false",
            "architecture": "arm64",
            "region": "US",
            "app_id": "com.duosecurity.duomobile",
            "full_disk_encryption": "true",
            "passcode_status": "true",
            "platform": "Android",
            "app_version": "3.49.0",
            "app_build–number": "323001",
            "version": "11",
            "language": "en",
            "security_patch_level": "2021-02-01",
            "model": "Device Name",
            "manufacturer": "unknown",
        }

        # Encode public key as PEM
        der_pub = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        b64_pub = base64.b64encode(der_pub).decode("ascii")

        pem_lines = ["-----BEGIN PUBLIC KEY-----"]
        for i in range(0, len(b64_pub), 64):
            pem_lines.append(b64_pub[i : i + 64])
        pem_lines.append("-----END PUBLIC KEY-----")
        params["pubkey"] = "\n".join(pem_lines)
        params["pkpush"] = "rsa-sha512"

        # Parse activation code
        try:
            identifier, host_b64 = activation_code.split("-", 1)
        except ValueError as e:
            raise ValueError(
                f"Invalid activation code format: {activation_code}"
            ) from e

        host = b64_fix(host_b64).decode(CHARSET)

        # Perform activation request
        url = f"https://{host}/push/v2/activation/{identifier}?{urlencode(params)}"

        try:
            resp = requests.post(url, timeout=15)
            resp.raise_for_status()
            response_data = resp.json()["response"]
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to activate device: {e}") from e
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid activation response: {e}") from e

        # Extract response fields
        akey = response_data["akey"]
        pkey = response_data["pkey"]

        # Try to find HOTP secret in various possible fields
        hotp_secret = (
            response_data.get("hotp_secret")
            or response_data.get("otp_secret")
            or response_data.get("otp_key")
            or response_data.get("seed")
        )

        # Prepare device data for storage
        der_pub_b64 = base64.b64encode(der_pub).decode(CHARSET)
        priv_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv_der_b64 = base64.b64encode(priv_der).decode(CHARSET)

        device_data = {
            "name": name or "default",
            "akey": akey,
            "pkey": pkey,
            "host": host,
            "public": der_pub_b64,
            "private": priv_der_b64,
        }

        if hotp_secret:
            device_data["hotp_secret"] = hotp_secret
            device_data["hotp_counter"] = 0

        # Save to disk
        storage.save_device(device_data, name)

        # Create and return device instance
        return cls(
            akey=akey,
            pkey=pkey,
            host=host,
            public_key=public_key,
            private_key=private_key,
            hotp_secret=hotp_secret,
            hotp_counter=0,
            name=name or "default",
        )

    @classmethod
    def load(cls, name: Optional[str] = None) -> "DuoDevice":
        """
        Load an existing device from disk.

        Args:
            name: Device name (default: "default").

        Returns:
            Loaded DuoDevice instance.

        Raises:
            FileNotFoundError: If the device file does not exist.
            ValueError: If the device file is invalid.
        """
        data = storage.load_device(name)

        # Decode keys
        try:
            der_pub = base64.b64decode(data["public"])
            der_priv = base64.b64decode(data["private"])
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid device file: missing or invalid keys: {e}") from e

        public_key = serialization.load_der_public_key(der_pub)
        private_key = serialization.load_der_private_key(der_priv, password=None)

        return cls(
            akey=data["akey"],
            pkey=data["pkey"],
            host=data["host"],
            public_key=public_key,
            private_key=private_key,
            hotp_secret=data.get("hotp_secret"),
            hotp_counter=int(data.get("hotp_counter", 0)),
            name=data.get("name", name or "default"),
        )

    def save(self) -> None:
        """Save device data to disk."""
        der_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        der_priv = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        device_data = {
            "name": self.name,
            "akey": self.akey,
            "pkey": self.pkey,
            "host": self.host,
            "public": base64.b64encode(der_pub).decode(CHARSET),
            "private": base64.b64encode(der_priv).decode(CHARSET),
        }

        if self.hotp_secret is not None:
            device_data["hotp_secret"] = self.hotp_secret
            device_data["hotp_counter"] = self.hotp_counter

        storage.save_device(device_data, self.name)

    def next_code(self, digits: int = 6, persist: bool = True) -> str:
        """
        Generate the next HOTP code.

        Args:
            digits: Number of digits in the code (default: 6).
            persist: Whether to increment and save the counter (default: True).

        Returns:
            HOTP code as a string.

        Raises:
            RuntimeError: If no HOTP secret is available for this device.
        """
        if self.hotp_secret is None:
            raise RuntimeError(
                "No HOTP secret available for this device. "
                "This device may not support HOTP code generation."
            )

        code = generate_hotp(self.hotp_secret, self.hotp_counter, digits)

        # Always increment counter (even if not persisting, for next call)
        self.hotp_counter += 1

        if persist:
            self.save()

        return code

