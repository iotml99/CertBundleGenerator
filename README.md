# SSL Certificate Bundle Generator

[![GitHub](https://img.shields.io/badge/GitHub-CertBundleGenerator-blue?logo=github)](https://github.com/iotml99/CertBundleGenerator)
[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A Python script that generates SSL certificate PEM bundles from a list of websites. The script retrieves SSL certificate contents from specified websites, deduplicates them, and creates a consolidated PEM bundle while respecting size limits and website priority ordering.

## Features

- 🔐 **SSL Certificate Retrieval**: Automatically fetches SSL certificates from websites
- 🔄 **Deduplication**: Removes duplicate certificates based on certificate content
- 📏 **Size Management**: Respects maximum bundle size limits with safety buffer
- 🎯 **Priority-Based Processing**: Processes websites in order of priority (first = highest priority)
- 📝 **Standard Logging**: Clean logging output using Python's built-in logging
- ⚡ **Error Handling**: Continues processing even when some websites fail
- 🌐 **Flexible Input**: Supports hostnames with or without protocols and custom ports
- ✅ **Bundle Validation**: Validates generated PEM bundles for format and integrity
- 📦 **No Dependencies**: Uses only Python standard library

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

## How It Works

1. **Input Processing**: Reads and parses the website list from the input file
2. **Certificate Retrieval**: For each website (in priority order):
   - Establishes SSL connection
   - Retrieves the server certificate
   - Converts from DER to PEM format
3. **Deduplication**: Uses SHA-256 hashing to identify and skip duplicate certificates
4. **Size Management**: 
   - Tracks running total of bundle size
   - Stops adding certificates when approaching max_size - 12 bytes
   - Ensures priority websites get included first
5. **Bundle Generation**: Concatenates all unique certificates into final PEM bundle

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
- **Dependencies**: No external dependencies - uses only Python standard library
- **SSL Context**: Uses Python's default SSL context for certificate validation
- **Certificate Format**: Generates standard PEM format with proper line breaks
- **Encoding**: All file operations use UTF-8 encoding
- **Timeout**: 10-second connection timeout for each website
- **Validation**: Comprehensive PEM format and content validation
- **Default Size**: 32KB default bundle size limit (adjustable with `-s` option)

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