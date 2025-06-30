# analyze_cert.py
# Analyzes bcorporation.net certificate

import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import os
import datetime

# Ensure PKI/certs directory exists
os.makedirs(r"C:\PKI\certs", exist_ok=True)

# Download certificate from bcorporation.net
website = "bcorporation.net"
port = 443
try:
    context = ssl.create_default_context()
    with socket.create_connection((website, port)) as sock:
        with context.wrap_socket(sock, server_hostname=website) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_der)
except Exception as e:
    print(f"Error downloading certificate from {website}:{port}: {e}")
    sys.exit(1)

# Save certificate
cert_path = r"C:\PKI\certs\bcorp.crt"
try:
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
except Exception as e:
    print(f"Error saving certificate to {cert_path}: {e}")
    sys.exit(1)

# Analyze certificate
analysis_path = r"C:\PKI\certs\bcorp_analysis.txt"
try:
    with open(analysis_path, "w", encoding="utf-8") as f:
        f.write(f"Issuer: {cert.issuer.rfc4514_string()}\n")
        f.write(f"Subject: {cert.subject.rfc4514_string()}\n")
        f.write(f"Serial Number: {cert.serial_number}\n")
        f.write(f"Not Before: {cert.not_valid_before_utc}\n")
        f.write(f"Not After: {cert.not_valid_after_utc}\n")
        for ext in cert.extensions:
            f.write(f"Extension: {ext.oid._name} = {ext.value}\n")
except Exception as e:
    print(f"Error writing analysis to {analysis_path}: {e}")
    sys.exit(1)

print(f"Certificate saved at {cert_path} and analysis at {analysis_path}")