"""Command-line interface for duo-hotp-auth."""

import argparse
import sys
from typing import Optional

from duo_hotp_auth.device import DuoDevice
from duo_hotp_auth import storage


def activate_command(args: argparse.Namespace) -> int:
    """Handle the activate command."""
    try:
        device = DuoDevice.activate(args.activation_code_or_url, name=args.name)
        print(f"✓ Device '{device.name}' activated successfully")
        print(f"  Host: {device.host}")
        print(f"  AKey: {device.akey[:20]}...")
        if device.hotp_secret:
            print(f"  HOTP: Available (counter: {device.hotp_counter})")
        else:
            print("  HOTP: Not available")
        return 0
    except Exception as e:
        print(f"✗ Activation failed: {e}", file=sys.stderr)
        return 1


def code_command(args: argparse.Namespace) -> int:
    """Handle the code command."""
    try:
        device = DuoDevice.load(name=args.name)
        code = device.next_code(digits=args.digits, persist=True)
        print(code)
        return 0
    except FileNotFoundError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"✗ Failed to generate code: {e}", file=sys.stderr)
        return 1


def list_command(args: argparse.Namespace) -> int:
    """Handle the list command."""
    try:
        devices = storage.list_devices()
        if not devices:
            print("No devices found. Activate a device first using:")
            print("  duo-hotp-activate <activation_code_or_url>")
            return 0

        print("Available devices:")
        for device_name in devices:
            try:
                device = DuoDevice.load(name=device_name)
                hotp_status = "HOTP available" if device.hotp_secret else "No HOTP"
                print(f"  {device_name}: {device.host} ({hotp_status})")
            except Exception:
                print(f"  {device_name}: (error loading)")
        return 0
    except Exception as e:
        print(f"✗ Failed to list devices: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Duo Mobile HOTP code generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Activate command
    activate_parser = subparsers.add_parser(
        "activate",
        aliases=["act"],
        help="Activate a new Duo Mobile device",
    )
    activate_parser.add_argument(
        "activation_code_or_url",
        help="Duo activation code or QR URL",
    )
    activate_parser.add_argument(
        "--name",
        "-n",
        default=None,
        help='Device name (default: "default")',
    )

    # Code command
    code_parser = subparsers.add_parser(
        "code",
        aliases=["generate", "gen"],
        help="Generate the next HOTP code",
    )
    code_parser.add_argument(
        "--name",
        "-n",
        default=None,
        help='Device name (default: "default")',
    )
    code_parser.add_argument(
        "--digits",
        "-d",
        type=int,
        default=6,
        choices=[6, 7, 8],
        help="Number of digits in the code (default: 6)",
    )

    # List command
    list_parser = subparsers.add_parser(
        "list",
        aliases=["ls"],
        help="List all activated devices",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command in ("activate", "act"):
        return activate_command(args)
    elif args.command in ("code", "generate", "gen"):
        return code_command(args)
    elif args.command in ("list", "ls"):
        return list_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

