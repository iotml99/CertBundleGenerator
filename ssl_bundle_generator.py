#!/usr/bin/env python3

import argparse
import socket
import ssl
import sys
import logging
import subprocess
import os
import tempfile
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
    
    def __init__(self, max_size: int, root_only: bool = False):
        self.max_size = max_size
        self.root_only = root_only
        self.certificates: List[Tuple[str, str]] = []  # (hostname, certificate_pem)
        self.seen_hashes: Set[str] = set()  # For deduplication
        self.current_size = 0
        self.total_certificates_processed = 0
        self.duplicate_certificates_skipped = 0
        
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

    def get_certificate_chain_openssl(self, hostname: str, port: int = 443) -> Optional[str]:
        """Retrieve full SSL certificate chain using OpenSSL command."""
        try:
            # Use OpenSSL to get the full certificate chain
            cmd = [
                'openssl', 's_client', 
                '-servername', hostname,
                '-connect', f'{hostname}:{port}',
                '-showcerts'
            ]
            
            # Run OpenSSL command
            result = subprocess.run(
                cmd, 
                input='',
                capture_output=True, 
                text=True, 
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            if result.returncode != 0:
                return None
                
            output = result.stdout
            
            # Extract certificates from OpenSSL output
            certificates = []
            lines = output.split('\n')
            current_cert = []
            in_cert = False
            
            for line in lines:
                line = line.strip()
                if line == '-----BEGIN CERTIFICATE-----':
                    in_cert = True
                    current_cert = [line]
                elif line == '-----END CERTIFICATE-----':
                    if in_cert:
                        current_cert.append(line)
                        certificates.append('\n'.join(current_cert))
                        current_cert = []
                        in_cert = False
                elif in_cert:
                    current_cert.append(line)
            
            if certificates:
                # Return all certificates in the chain (server + intermediates)
                chain = '\n'.join(certificates)
                self.log_success(f"Retrieved certificate chain for {hostname}:{port} ({len(certificates)} certificates)")
                return chain
            
            return None
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            # OpenSSL not available or failed, fall back to Python SSL
            return None
        except Exception:
            return None

    def get_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[str]:
        """Retrieve SSL certificate chain from hostname:port."""
        # First try to get the full certificate chain using OpenSSL
        cert_chain = self.get_certificate_chain_openssl(hostname, port)
        if cert_chain:
            return cert_chain
            
        # Fall back to Python SSL (server certificate only)
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format (server certificate only)
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
                    
                    self.log_success(f"Retrieved certificate for {hostname}:{port} (server cert only)")
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

    def split_certificate_chain(self, cert_chain_pem: str) -> List[str]:
        """Split a certificate chain into individual certificates."""
        certificates = []
        lines = cert_chain_pem.split('\n')
        current_cert = []
        in_cert = False
        
        for line in lines:
            line = line.strip()
            if line == '-----BEGIN CERTIFICATE-----':
                in_cert = True
                current_cert = [line]
            elif line == '-----END CERTIFICATE-----':
                if in_cert:
                    current_cert.append(line)
                    certificates.append('\n'.join(current_cert))
                    current_cert = []
                    in_cert = False
            elif in_cert:
                current_cert.append(line)
        
        return certificates
    
    def is_root_ca_certificate(self, cert_pem: str) -> bool:
        """Check if a certificate is a root CA (self-signed)."""
        try:
            # Use openssl to parse the certificate and check if self-signed
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp_file:
                tmp_file.write(cert_pem)
                tmp_file.flush()
                
                try:
                    # Get certificate subject and issuer
                    result = subprocess.run([
                        'openssl', 'x509', '-in', tmp_file.name, '-noout', '-subject', '-issuer'
                    ], capture_output=True, text=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                    
                    if result.returncode == 0:
                        output = result.stdout
                        subject_line = None
                        issuer_line = None
                        
                        for line in output.split('\n'):
                            if line.startswith('subject='):
                                subject_line = line[8:].strip()
                            elif line.startswith('issuer='):
                                issuer_line = line[7:].strip()
                        
                        # Root CA is self-signed (subject == issuer)
                        if subject_line and issuer_line:
                            return subject_line == issuer_line
                            
                finally:
                    os.unlink(tmp_file.name)
                    
        except Exception:
            # If we can't determine, assume it's not a root CA
            pass
            
        # Fallback: assume the last certificate in a chain is the root
        return False
    
    def filter_certificates_by_type(self, certificates: List[str]) -> List[str]:
        """Filter certificates based on root_only setting."""
        if not self.root_only:
            return certificates
        
        # In root-only mode, keep only root CA certificates
        root_certs = []
        for cert in certificates:
            if self.is_root_ca_certificate(cert):
                root_certs.append(cert)
        
        # If we can't identify root CAs using OpenSSL, use heuristic: last cert is usually root
        if not root_certs and certificates:
            root_certs = [certificates[-1]]  # Last certificate in chain is typically the root
            
        return root_certs

    def add_certificate(self, hostname: str, cert_pem: str) -> bool:
        """Add certificate chain to bundle, deduplicating individual certificates."""
        # Split chain into individual certificates
        individual_certs = self.split_certificate_chain(cert_pem)
        
        if not individual_certs:
            self.log_error(f"No valid certificates found in chain for {hostname}")
            return False
        
        # Filter certificates based on mode (all or root-only)
        filtered_certs = self.filter_certificates_by_type(individual_certs)
        
        if not filtered_certs:
            if self.root_only:
                self.log_warning(f"No root CA certificates found for {hostname}")
            return False
        
        # Track which certificates we're adding for this hostname
        new_certs = []
        total_new_size = 0
        duplicates_found = 0
        
        # Check each certificate in the filtered set
        for cert in filtered_certs:
            self.total_certificates_processed += 1
            cert_hash = self.get_certificate_hash(cert)
            
            if cert_hash in self.seen_hashes:
                duplicates_found += 1
                self.duplicate_certificates_skipped += 1
                self.log_warning(f"Duplicate certificate found in chain for {hostname}, skipping")
            else:
                cert_size = len(cert.encode('utf-8'))
                if (self.current_size + total_new_size + cert_size) <= (self.max_size - 12):
                    new_certs.append(cert)
                    total_new_size += cert_size
                else:
                    self.log_warning(f"Size limit reached, cannot add remaining certificates for {hostname}")
                    break
        
        # If we couldn't add any new certificates, check if it's all duplicates
        if not new_certs:
            if duplicates_found == len(filtered_certs):
                self.log_warning(f"All certificates for {hostname} are duplicates, skipping")
                return True  # Not an error, just all duplicates
            else:
                self.log_warning(f"Size limit reached, cannot add certificates for {hostname}")
                return False
        
        # Add the new certificates
        for cert in new_certs:
            cert_hash = self.get_certificate_hash(cert)
            self.seen_hashes.add(cert_hash)
        
        # Store as a reconstructed chain (only new certificates)
        reconstructed_chain = '\n'.join(new_certs)
        self.certificates.append((hostname, reconstructed_chain))
        self.current_size += total_new_size
        
        added_count = len(new_certs)
        total_count = len(filtered_certs)
        cert_type = "root CAs" if self.root_only else "certificates"
        self.log_success(f"Added {added_count}/{total_count} {cert_type} for {hostname} (size: {total_new_size} bytes, {duplicates_found} duplicates)")
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
                
            # Count expected certificates (each website entry may have multiple certs in chain)
            expected_cert_count = 0
            for _, cert_pem in self.certificates:
                # Count certificates in this entry
                expected_cert_count += cert_pem.count("-----BEGIN CERTIFICATE-----")
            
            # Validate that we have the expected number of certificates
            if cert_count != expected_cert_count:
                self.log_error(f"Certificate count mismatch: expected {expected_cert_count}, found {cert_count}")
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
    
    parser.add_argument(
        '--root-only',
        action='store_true',
        help='Include only root CA certificates (smallest bundle, may not work with all SSL clients)'
    )
    
    args = parser.parse_args()
    
    # Initialize the generator
    generator = SSLBundleGenerator(args.max_size, args.root_only)
    
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
                
                # Count total unique certificates in the bundle
                total_certs_in_bundle = sum(cert_chain.count("-----BEGIN CERTIFICATE-----") for _, cert_chain in generator.certificates)
                
                generator.log_success("Bundle created successfully!")
                generator.log_info(f"Processed: {processed} websites")
                generator.log_info(f"Total certificates found: {generator.total_certificates_processed}")
                generator.log_info(f"Duplicate certificates skipped: {generator.duplicate_certificates_skipped}")
                generator.log_info(f"Unique certificates in bundle: {total_certs_in_bundle}")
                generator.log_info(f"Final bundle size: {final_size} bytes")
                generator.log_info(f"Output written to: {args.output}")
                
                if generator.duplicate_certificates_skipped > 0:
                    savings_pct = (generator.duplicate_certificates_skipped / generator.total_certificates_processed) * 100
                    generator.log_info(f"Deduplication saved {generator.duplicate_certificates_skipped} certificates ({savings_pct:.1f}% reduction)")
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