# SSL Certificate Bundle Generator

[![GitHub](https://img.shields.io/badge/GitHub-CertBundleGenerator-blue?logo=github)](https://github.com/iotml99/CertBundleGenerator)
[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A Python script that generates SSL certificate PEM bundles from a list of websites. The script retrieves SSL certificate contents from specified websites, deduplicates them, and creates a consolidated PEM bundle while respecting size limits and website priority ordering.

## Features

- 🔐 **Full Certificate Chain Retrieval**: Automatically fetches complete SSL certificate chains (server + intermediate certificates) from websites
- 🔄 **Deduplication**: Removes duplicate certificates based on certificate content
- 📏 **Size Management**: Respects maximum bundle size limits with safety buffer
- 🎯 **Priority-Based Processing**: Processes websites in order of priority (first = highest priority)
- 📝 **Standard Logging**: Clean logging output using Python's built-in logging
- ⚡ **Error Handling**: Continues processing even when some websites fail
- 🌐 **Flexible Input**: Supports hostnames with or without protocols and custom ports
- ✅ **Bundle Validation**: Validates generated PEM bundles for format and integrity
- �️ **Smart Chain Detection**: Uses OpenSSL when available for full chains, falls back to Python SSL for server certificates
- �📦 **Minimal Dependencies**: Uses only Python standard library + OpenSSL (optional but recommended)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/iotml99/CertBundleGenerator.git
cd CertBundleGenerator

# Create a websites.txt file with your target websites
echo -e "google.com\ngithub.com\nstackoverflow.com" > websites.txt

# Generate SSL certificate bundle
python ssl_bundle_generator.py -i websites.txt -o bundle.pem -s 32768
```

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/iotml99/CertBundleGenerator.git
   cd CertBundleGenerator
   ```

2. **No external dependencies required**
   The script uses only Python's standard library - no additional packages needed!
   
   **Optional**: For full certificate chain support, ensure OpenSSL is available in your PATH:
   - **Windows**: Download from [Win32/Win64 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)
   - **macOS**: `brew install openssl` 
   - **Linux**: Usually pre-installed, or `sudo apt-get install openssl`

## Usage

### Basic Usage

```bash
python ssl_bundle_generator.py -i websites.txt -o bundle.pem -s 32768
```

### Command Line Arguments

| Argument | Short | Description | Required | Default |
|----------|-------|-------------|----------|---------|
| `--input` | `-i` | Input file containing websites (one per line) | Yes | - |
| `--output` | `-o` | Output file for the PEM bundle | Yes | - |
| `--max-size` | `-s` | Maximum size of PEM bundle in bytes | No | 32768 (32KB) |
| `--root-only` | - | Include only root CA certificates (smaller bundle, may reduce compatibility) | No | False |

### Input File Format

Create a text file with one website per line. The script supports various formats:

```text
# Comments (lines starting with #) are ignored
google.com
https://github.com
facebook.com:443
https://stackoverflow.com:443
example.com

# Empty lines are also ignored
```

**Supported formats:**
- `hostname.com` (assumes port 443)
- `hostname.com:port`
- `https://hostname.com`
- `https://hostname.com:port`

## Examples

### Example 1: Basic Certificate Bundle
```bash
python ssl_bundle_generator.py -i websites.txt -o certificates.pem
```

### Example 2: Large Bundle with Custom Size Limit
```bash
python ssl_bundle_generator.py -i high-priority-sites.txt -o large-bundle.pem -s 65536
```

### Example 3: Small Bundle for Embedded Systems
```bash
python ssl_bundle_generator.py -i critical-sites.txt -o small-bundle.pem -s 16384
```

### Example 4: Root CA Only Bundle (Minimal Size)
```bash
python ssl_bundle_generator.py -i websites.txt -o root-cas.pem --root-only
```

## Sample Input File

Create a file named `websites.txt`:

```text
# High priority websites (processed first)
google.com
github.com
stackoverflow.com
python.org

# Medium priority
mozilla.org
cloudflare.com

# Lower priority
example.com
httpbin.org
```

## Output

The script generates a PEM bundle file containing certificates in the following format:

```
-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgIQTkuN...
...certificate content...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgIQTkuN...
...next certificate content...
-----END CERTIFICATE-----
```

## Logging

The script provides clear logging with different message types:

- **INFO** - General information and successful operations
- **WARNING** - Non-fatal issues (duplicates, size limits)
- **ERROR** - Errors that don't stop execution

### Sample Output

```
INFO: Reading websites from: websites.txt
INFO: Found 8 lines in input file
INFO: Starting certificate collection (max size: 32768 bytes)
INFO: Processing google.com:443
INFO: SUCCESS: Retrieved certificate for google.com:443
INFO: SUCCESS: Added certificate for google.com (size: 1289 bytes)
INFO: Processing github.com:443
INFO: SUCCESS: Retrieved certificate for github.com:443
INFO: SUCCESS: Added certificate for github.com (size: 1654 bytes)
ERROR: Connection timeout for unreachable-site.com:443
INFO: SUCCESS: Bundle validation passed: 6 certificates, 8934 bytes
INFO: SUCCESS: Bundle created successfully!
INFO: Processed: 6 websites
INFO: Certificates in bundle: 6
INFO: Final bundle size: 8934 bytes
INFO: Output written to: bundle.pem
```

## Certificate Chain vs Root-Only Modes

### 🔗 Full Certificate Chain Mode (Default)
- **What it includes**: Server certificates + intermediate certificates + root CA certificates
- **Bundle size**: Larger (typically 3x more certificates)
- **Compatibility**: Works with all SSL clients and browsers
- **Use case**: Production environments, public-facing applications

### 🏛️ Root-Only Mode (`--root-only`)
- **What it includes**: Only root CA certificates (trust anchors)
- **Bundle size**: Much smaller (75% size reduction typical)
- **Compatibility**: Limited - may not work with all SSL clients
- **Use case**: Embedded systems, memory-constrained environments, CA trust store initialization

### 📊 Comparison Example

| Mode | Certificates | Bundle Size | Compatibility | Best For |
|------|-------------|-------------|---------------|----------|
| **Full Chain** | 14 certs | 36 KB | ✅ Universal | Production, web apps |
| **Root-Only** | 5 certs | 9 KB | ⚠️ Limited | Embedded, trust stores |

## How It Works

1. **Input Processing**: Reads and parses the website list from the input file
2. **Certificate Chain Retrieval**: For each website (in priority order):
   - **Primary Method**: Uses OpenSSL command-line tool to retrieve complete certificate chain (server + intermediate certificates)
   - **Fallback Method**: If OpenSSL unavailable, uses Python SSL to retrieve server certificate only
   - Establishes SSL connection with proper hostname verification
   - Converts certificates from DER to PEM format
3. **Certificate Filtering**: 
   - **Default Mode**: Includes all certificates in the chain
   - **Root-Only Mode**: Extracts and includes only root CA certificates (self-signed certificates)
4. **Deduplication**: Uses SHA-256 hashing to identify and skip duplicate certificates across all chains
5. **Size Management**: 
   - Tracks running total of bundle size including all certificates in chains
   - Stops adding certificates when approaching max_size - 12 bytes
   - Ensures priority websites get included first
6. **Bundle Generation**: Concatenates all unique certificates from all chains into final PEM bundle
7. **Chain Validation**: Validates complete certificate chains for proper PEM structure and content

## Error Handling

The script handles various error conditions gracefully:

- **DNS Resolution Failures**: Logs error and continues with next website
- **Connection Timeouts**: 10-second timeout, logs error and continues
- **SSL Errors**: Logs SSL-specific errors and continues
- **Invalid Hostnames**: Logs parsing errors and continues
- **File I/O Errors**: Reports file access issues and exits

## Size Management

The script implements intelligent size management:

- **Safety Buffer**: Reserves 12 bytes below max_size limit
- **Priority-First**: Higher priority websites (earlier in file) are processed first
- **Early Termination**: Stops processing when size limit would be exceeded
- **Accurate Tracking**: Tracks exact byte size of UTF-8 encoded PEM content

## Technical Details

- **Python Version**: Compatible with Python 3.6+
- **Dependencies**: 
  - **Required**: Python standard library only
  - **Optional**: OpenSSL command-line tool (for complete certificate chains and root CA detection)
- **Certificate Chain Retrieval**:
  - **Primary**: OpenSSL `s_client -showcerts` command (retrieves full chains)
  - **Fallback**: Python `ssl.getpeercert()` (server certificate only)
- **Root CA Detection**:
  - **Method 1**: OpenSSL `x509 -subject -issuer` to identify self-signed certificates
  - **Method 2**: Heuristic fallback (last certificate in chain)
- **SSL Context**: Uses Python's default SSL context for certificate validation
- **Certificate Format**: Generates standard PEM format with proper line breaks
- **Encoding**: All file operations use UTF-8 encoding
- **Timeout**: 15-second timeout for OpenSSL, 10-second for Python SSL
- **Validation**: Comprehensive PEM format and content validation for certificate chains
- **Default Size**: 32KB default bundle size limit (adjustable with `-s` option)
- **Chain Support**: Handles variable-length certificate chains (2-4 certificates typical)
- **Deduplication**: Individual certificate-level deduplication across all websites

## Troubleshooting

### Common Issues

1. **"Connection timeout"**
   - Website may be down or blocking connections
   - Try increasing timeout in the code if needed

2. **"SSL error"**
   - Website may have invalid or expired certificates
   - Script will log error and continue with other websites

3. **"DNS resolution failed"**
   - Check website hostname spelling
   - Ensure internet connectivity

4. **"Size limit reached"**
   - Increase `-s` or `--max-size` parameter
   - Remove lower priority websites from input file

5. **"Bundle validation failed"**
   - Check for corrupted certificates or invalid PEM format
   - Verify bundle size is within specified limits

6. **Missing intermediate certificates**
   - Install OpenSSL for complete certificate chain support
   - Without OpenSSL, only server certificates are included
   - Some applications require full certificate chains for proper SSL validation

7. **Root-only mode not working**
   - Root-only bundles may not work with all SSL clients
   - Missing intermediate certificates can cause validation failures
   - Use full chain mode for better compatibility
   - Consider root-only only for specific use cases (embedded systems, CA trust stores)

### Performance Tips

- Place highest priority websites at the top of input file
- Use reasonable max-size limits to avoid memory issues
- Remove or comment out problematic websites that consistently fail

## License

This script is provided as-is for educational and practical purposes. Please ensure compliance with website terms of service when retrieving certificates.

## Repository

🔗 **GitHub**: [https://github.com/iotml99/CertBundleGenerator](https://github.com/iotml99/CertBundleGenerator)

## Contributing

Contributions are welcome! Feel free to:

- 🐛 Submit [bug reports](https://github.com/iotml99/CertBundleGenerator/issues)
- 💡 Propose [feature requests](https://github.com/iotml99/CertBundleGenerator/issues)
- 🔧 Submit [pull requests](https://github.com/iotml99/CertBundleGenerator/pulls) for improvements

Please ensure your code follows the existing style and includes appropriate tests.