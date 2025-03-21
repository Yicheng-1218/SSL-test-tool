# SSL Test Tool

A command-line tool for testing website SSL/TLS configurations. This tool checks various security parameters including TLS version support, SSL certificate validity, cipher suites, and more.

## Features

- TLS version support detection (TLS 1.0 ~ 1.3)
- SSL certificate validity check
- OCSP certificate status verification
- Cipher suite strength evaluation
- PFS (Perfect Forward Secrecy) support detection
- HSTS implementation check
- Automatic test report generation with clipboard copy

## Requirements

- Python 3.10 or higher
- Windows/Linux/macOS

## Installation

1. Clone this repository:
```bash
git clone [repository-url]
cd ssl-test
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows
```

3. Install dependencies:

Option 1 - Using requirements.txt:
```bash
pip install -r requirements.txt
```

Option 2 - Using uv install:
```bash
uv add -r requirements.txt
```

## Usage

Run the Python script:
```bash
python main.py
```

After launching:
1. Enter the website URL to test (defaults to www.google.com)
2. View the test results
3. Test report will be automatically copied to clipboard
4. Press Enter to continue testing other websites

## Creating Executable

You can package the program into a single executable using PyInstaller:

```bash
# Install PyInstaller
pip install pyinstaller

# Package the program
pyinstaller main.spec
```

The executable will be available in the `dist` directory after packaging.

## Test Report Contents

The test report includes:
- TLS version support status
- SSL certificate validity period
- OCSP certificate status
- Cipher suite strength
- PFS support status
- HSTS implementation status

## Notes
- Internet connection is required for testing
- Some websites may refuse connections due to security settings
- Test results are for reference only; professional assessment is recommended for security configurations

## License
This project is licensed under the MIT License.