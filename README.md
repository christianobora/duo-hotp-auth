# duo-hotp-auth

Duo Mobile HOTP code generator based on Duo activation links.

This is an **unofficial** Python library that allows you to activate Duo Mobile devices from Duo activation codes (or QR URLs) and generate HOTP codes using the stored device secrets.

## Features

- ✅ Activate Duo Mobile devices from activation codes or QR URLs
- ✅ Store device information securely on disk (per-user appdata directory)
- ✅ Generate HOTP codes using RFC 4226 (HMAC-SHA1)
- ✅ Automatic counter management
- ✅ Cross-platform storage (Windows, macOS, Linux)
- ✅ Command-line interface
- ✅ Clean Python API

## Installation

```bash
pip install duo-hotp-auth
```

## Getting Your Duo Activation Code

Before you can activate a device, you need to obtain the Duo activation code or QR URL from your Duo account:

1. **Log in to your Duo account on web** (or wherever your duo 2FA is managed)
2. **Add a new device**:
   - Navigate to your account settings
   - Select "Add a new device" or "Add another device"
   - Choose device type: **Tablet** or **iOS** (iPhone/iPad)
3. **Get the activation code/URL**:
   - When the QR code appears on screen, **right-click** (or Control+click on macOS) on the QR code image
   - Select **"Copy image address"** or **"Copy image URL"** from the context menu
   - This will copy a URL like: `https://api-xxxx.duosecurity.com/frame/qr?value=duo%3A%2F%2F...`
4. **Use the copied URL** with the activation command (see Usage below)

**Alternative**: If you can see the raw activation code (a string like `test123...-YXBp...`), you can use that directly instead of the QR URL.

## Usage

### Python API

#### Activate a device

```python
from duo_hotp_auth import DuoDevice

# From a QR URL
device = DuoDevice.activate(
    "https://api-xxxx.duosecurity.com/frame/qr?value=duo%3A%2F%2F...",
    name="my-phone"
)

# Or from a raw activation code
device = DuoDevice.activate("test123...-YXBp...", name="my-phone")
```

#### Generate HOTP codes

```python
# Load an existing device
device = DuoDevice.load(name="my-phone")

# Generate the next HOTP code (counter increments automatically)
code = device.next_code()
print(code)  # e.g., "123456"

# Generate with custom digit count
code = device.next_code(digits=8)

# Generate without persisting counter (for testing)
code = device.next_code(persist=False)
```

### Command-Line Interface

#### Activate a device

```bash
duo-hotp activate "https://api-xxxx.duosecurity.com/frame/qr?value=duo%3A%2F%2F..." --name my-phone
```

Or using a raw activation code:

```bash
duo-hotp activate "test123...-YXBp..." -n my-phone
```

#### Generate a code

```bash
duo-hotp code --name my-phone
```

Or with custom digits:

```bash
duo-hotp code -n my-phone -d 8
```

#### List all devices

```bash
duo-hotp list
```

## Storage

Device information is stored in a cross-platform appdata directory:

- **Windows**: `%APPDATA%\duo-hotp-auth\duo-hotp-auth\`
- **macOS**: `~/Library/Application Support/duo-hotp-auth/`
- **Linux**: `~/.local/share/duo-hotp-auth/`

Each device is stored as a JSON file (e.g., `default.json`, `my-phone.json`).

## Security Notes

⚠️ **Important**: This library stores device keys and HOTP secrets on disk. You are responsible for:

- Securing the device files (file permissions, encryption at rest, etc.)
- Complying with Duo's terms of service
- Using this library in accordance with your organization's security policies

This is an **unofficial** library and is not affiliated with or endorsed by Duo Security.

## Development

```bash
# Clone the repository
git clone https://github.com/christianobora/duo-hotp-auth.git
cd duo-hotp-auth

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

This library is provided as-is for educational and legitimate use cases. The authors are not responsible for any misuse or security issues that may arise from using this software. Always ensure you have proper authorization before activating devices and generating codes.

