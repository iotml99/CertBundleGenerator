#!/usr/bin/env python3

import argparse
import socket
import ssl
import sys
import logging
from typing import Set, List, Tuple, Optional
from urllib.parse import urlparse
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)

class SSLBundleGenerator:
    """Generate SSL certificate bundles from a list of websites."""
    
    def __init__(self, max_size: int):
        self.max_size = max_size
        self.certificates: List[Tuple[str, str]] = []  # (hostname, certificate_pem)
        self.seen_hashes: Set[str] = set()  # For deduplication
        self.current_size = 0
        
    def log_info(self, message: str):
        """Log info message."""
        logging.info(message)
        
    def log_success(self, message: str):
        """Log success message."""
        logging.info(f"SUCCESS: {message}")
        
    def log_warning(self, message: str):
        """Log warning message."""
        logging.warning(message)
        
    def log_error(self, message: str):
        """Log error message."""
        logging.error(message)

    def parse_hostname(self, url: str) -> Tuple[str, int]:
        """Parse hostname and port from URL or hostname string."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        if not hostname:
            raise ValueError(f"Invalid hostname: {url}")
            
        return hostname, port

    def get_certificate_hash(self, cert_pem: str) -> str:
        """Generate a hash for certificate deduplication."""
        return hashlib.sha256(cert_pem.encode('utf-8')).hexdigest()

    def get_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[str]:
        """Retrieve SSL certificate from hostname:port."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)
                    
                    if not der_cert:
                        self.log_error(f"No certificate found for {hostname}:{port}")
                        return None
                    
                    # Convert DER to PEM format
                    import base64
                    pem_cert = "-----BEGIN CERTIFICATE-----\n"
                    pem_cert += base64.b64encode(der_cert).decode('ascii')
                    
                    # Insert line breaks every 64 characters
                    pem_lines = []
                    for i in range(0, len(pem_cert) - len("-----BEGIN CERTIFICATE-----\n"), 64):
                        line_start = len("-----BEGIN CERTIFICATE-----\n") + i
                        line_end = line_start + 64
                        if line_end > len(pem_cert):
                            pem_lines.append(pem_cert[line_start:])
                        else:
                            pem_lines.append(pem_cert[line_start:line_end])
                    
                    pem_cert = "-----BEGIN CERTIFICATE-----\n"
                    pem_cert += "\n".join(pem_lines)
                    pem_cert += "\n-----END CERTIFICATE-----"
                    
                    self.log_success(f"Retrieved certificate for {hostname}:{port}")
                    return pem_cert
                    
        except socket.timeout:
            self.log_error(f"Connection timeout for {hostname}:{port}")
        except socket.gaierror as e:
            self.log_error(f"DNS resolution failed for {hostname}: {e}")
        except ssl.SSLError as e:
            self.log_error(f"SSL error for {hostname}:{port}: {e}")
        except ConnectionRefusedError:
            self.log_error(f"Connection refused for {hostname}:{port}")
        except Exception as e:
            self.log_error(f"Unexpected error for {hostname}:{port}: {e}")
            
        return None

    def can_add_certificate(self, cert_pem: str) -> bool:
        """Check if certificate can be added without exceeding size limit."""
        cert_size = len(cert_pem.encode('utf-8'))
        safety_buffer = 12
        return (self.current_size + cert_size) <= (self.max_size - safety_buffer)

    def add_certificate(self, hostname: str, cert_pem: str) -> bool:
        """Add certificate to bundle if not duplicate and within size limit."""
        cert_hash = self.get_certificate_hash(cert_pem)
        
        # Check for duplicates
        if cert_hash in self.seen_hashes:
            self.log_warning(f"Duplicate certificate found for {hostname}, skipping")
            return True  # Not an error, just a duplicate
            
        # Check size limit
        if not self.can_add_certificate(cert_pem):
            self.log_warning(f"Size limit reached, cannot add certificate for {hostname}")
            return False
            
        # Add certificate
        self.certificates.append((hostname, cert_pem))
        self.seen_hashes.add(cert_hash)
        self.current_size += len(cert_pem.encode('utf-8'))
        
        self.log_success(f"Added certificate for {hostname} (size: {len(cert_pem)} bytes)")
        return True

    def process_websites(self, websites: List[str]) -> int:
        """Process list of websites and collect their certificates."""
        processed = 0
        
        for website in websites:
            website = website.strip()
            if not website or website.startswith('#'):
                continue
                
            try:
                hostname, port = self.parse_hostname(website)
                self.log_info(f"Processing {hostname}:{port}")
                
                cert_pem = self.get_ssl_certificate(hostname, port)
                if cert_pem:
                    if not self.add_certificate(hostname, cert_pem):
                        # Size limit reached, stop processing
                        self.log_warning("Maximum bundle size reached, stopping")
                        break
                    processed += 1
                else:
                    self.log_error(f"Failed to retrieve certificate for {hostname}:{port}")
                    
            except ValueError as e:
                self.log_error(f"Invalid website format '{website}': {e}")
            except Exception as e:
                self.log_error(f"Unexpected error processing '{website}': {e}")
                
        return processed

    def generate_bundle(self) -> str:
        """Generate the final PEM bundle."""
        if not self.certificates:
            return ""
            
        bundle_parts = []
        for hostname, cert_pem in self.certificates:
            bundle_parts.append(cert_pem)
            
        return "\n".join(bundle_parts)

    def validate_bundle(self, bundle: str) -> bool:
        """Validate the generated PEM bundle."""
        if not bundle:
            self.log_warning("Empty bundle - nothing to validate")
            return True
            
        try:
            # Check for proper PEM format
            lines = bundle.split('\n')
            cert_count = 0
            in_certificate = False
            
            for line in lines:
                line = line.strip()
                if line == "-----BEGIN CERTIFICATE-----":
                    if in_certificate:
                        self.log_error("Invalid PEM format: nested BEGIN CERTIFICATE")
                        return False
                    in_certificate = True
                elif line == "-----END CERTIFICATE-----":
                    if not in_certificate:
                        self.log_error("Invalid PEM format: END CERTIFICATE without BEGIN")
                        return False
                    in_certificate = False
                    cert_count += 1
                elif in_certificate:
                    # Validate base64 content
                    if not line:
                        continue
                    try:
                        import base64
                        base64.b64decode(line, validate=True)
                    except Exception:
                        self.log_error(f"Invalid base64 content in certificate: {line[:50]}...")
                        return False
            
            if in_certificate:
                self.log_error("Invalid PEM format: unclosed certificate block")
                return False
                
            # Validate that we have the expected number of certificates
            if cert_count != len(self.certificates):
                self.log_error(f"Certificate count mismatch: expected {len(self.certificates)}, found {cert_count}")
                return False
                
            # Validate bundle size
            bundle_size = len(bundle.encode('utf-8'))
            if bundle_size > self.max_size:
                self.log_error(f"Bundle size {bundle_size} exceeds maximum {self.max_size}")
                return False
                
            self.log_success(f"Bundle validation passed: {cert_count} certificates, {bundle_size} bytes")
            return True
            
        except Exception as e:
            self.log_error(f"Bundle validation failed: {e}")
            return False

def read_websites_file(filepath: str) -> List[str]:
    """Read websites from input file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.readlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {filepath}")
    except Exception as e:
        raise Exception(f"Error reading input file: {e}")

def write_bundle_file(filepath: str, bundle: str):
    """Write PEM bundle to output file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(bundle)
    except Exception as e:
        raise Exception(f"Error writing output file: {e}")

def main():
    """Main function to handle command line arguments and orchestrate the process."""
    parser = argparse.ArgumentParser(
        description='Generate SSL certificate PEM bundles from a list of websites',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssl_bundle_generator.py -i websites.txt -o bundle.pem -s 65536
  python ssl_bundle_generator.py --input sites.txt --output certs.pem --max-size 32768
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Input file containing websites (one per line)'
    )
    
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output file for the PEM bundle'
    )
    
    parser.add_argument(
        '-s', '--max-size',
        type=int,
        default=32768,  # 32KB default
        help='Maximum size of the PEM bundle in bytes (default: 32768)'
    )
    
    args = parser.parse_args()
    
    # Initialize the generator
    generator = SSLBundleGenerator(args.max_size)
    
    try:
        # Read websites from input file
        generator.log_info(f"Reading websites from: {args.input}")
        websites = read_websites_file(args.input)
        generator.log_info(f"Found {len(websites)} lines in input file")
        
        # Process websites
        generator.log_info(f"Starting certificate collection (max size: {args.max_size} bytes)")
        processed = generator.process_websites(websites)
        
        # Generate bundle
        bundle = generator.generate_bundle()
        
        if bundle:
            # Validate bundle before writing
            if generator.validate_bundle(bundle):
                # Write output
                write_bundle_file(args.output, bundle)
                
                final_size = len(bundle.encode('utf-8'))
                generator.log_success("Bundle created successfully!")
                generator.log_info(f"Processed: {processed} websites")
                generator.log_info(f"Certificates in bundle: {len(generator.certificates)}")
                generator.log_info(f"Final bundle size: {final_size} bytes")
                generator.log_info(f"Output written to: {args.output}")
            else:
                generator.log_error("Bundle validation failed, not writing output")
                sys.exit(1)
        else:
            generator.log_warning("No certificates collected, empty bundle generated")
            write_bundle_file(args.output, "")
            
    except KeyboardInterrupt:
        generator.log_warning("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        generator.log_error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()