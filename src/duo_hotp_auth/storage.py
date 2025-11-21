"""Storage utilities for persisting Duo device information."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from platformdirs import user_data_dir
except ImportError:
    # Fallback for older Python versions
    try:
        from appdirs import user_data_dir
    except ImportError:
        # Last resort: use home directory
        def user_data_dir(appname: str, appauthor: str) -> str:
            return str(Path.home() / f".{appname}")


APP_NAME = "duo-hotp-auth"
APP_AUTHOR = "duo-hotp-auth"


def get_storage_dir() -> Path:
    """
    Get the cross-platform appdata directory for storing device files.

    Returns:
        Path to the storage directory.
    """
    base_dir = user_data_dir(APP_NAME, APP_AUTHOR)
    return Path(base_dir)


def get_device_path(name: Optional[str] = None) -> Path:
    """
    Get the file path for a device by name.

    Args:
        name: Device name (default: "default").

    Returns:
        Path to the device JSON file.
    """
    storage_dir = get_storage_dir()
    device_name = name or "default"
    return storage_dir / f"{device_name}.json"


def save_device(data: Dict[str, Any], name: Optional[str] = None) -> None:
    """
    Save device data to disk.

    Args:
        data: Device data dictionary.
        name: Device name (default: "default").
    """
    device_path = get_device_path(name)
    device_path.parent.mkdir(parents=True, exist_ok=True)

    # Ensure name is set in data
    if "name" not in data:
        data["name"] = name or "default"

    # Write atomically using a temporary file
    temp_path = device_path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temp_path.replace(device_path)


def load_device(name: Optional[str] = None) -> Dict[str, Any]:
    """
    Load device data from disk.

    Args:
        name: Device name (default: "default").

    Returns:
        Device data dictionary.

    Raises:
        FileNotFoundError: If the device file does not exist.
        ValueError: If the device file contains invalid JSON.
    """
    device_path = get_device_path(name)
    if not device_path.exists():
        device_name = name or "default"
        raise FileNotFoundError(
            f"Device '{device_name}' not found at {device_path}. "
            "Activate a device first using DuoDevice.activate()."
        )

    try:
        content = device_path.read_text(encoding="utf-8")
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid device file format: {e}") from e


def list_devices() -> list[str]:
    """
    List all available device names.

    Returns:
        List of device names (without .json extension).
    """
    storage_dir = get_storage_dir()
    if not storage_dir.exists():
        return []

    devices = []
    for path in storage_dir.glob("*.json"):
        if path.name != ".tmp":
            devices.append(path.stem)
    return sorted(devices)

