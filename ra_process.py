# ra_process.py
# Issues certificate for bcorporation.net based on CSR

import sys
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime

# Parse arguments
if len(sys.argv) != 3:
    print("Usage: python ra_process.py <csr_path> <user_id>")
    sys.exit(1)
csr_path = sys.argv[1]
user_id = sys.argv[2]

# Validate CSR
if not os.path.exists(csr_path):
    print(f"Error: CSR file not found: {csr_path}")
    sys.exit(1)

# Simulate identity verification
approved_users = ["bcorp"]
if user_id not in approved_users:
    print(f"Error: User {user_id} not authorized")
    sys.exit(1)

# Load CSR
with open(csr_path, "rb") as f:
    csr = x509.load_pem_x509_csr(f.read())

# Load Root CA key and certificate
with open(r"C:\PKI\keys\root_ca.key", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)
with open(r"C:\PKI\ca\root_ca.crt", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Issue certificate
cert = x509.CertificateBuilder().subject_name(
    csr.subject
).issuer_name(
    ca_cert.subject
).public_key(
    csr.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("bcorporation.net")]),
    critical=False
).add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
).add_extension(
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
    critical=False
).sign(ca_key, hashes.SHA256())

# Save certificate
cert_path = rf"C:\PKI\certs\{user_id}.crt"
with open(cert_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"Certificate issued for {user_id} at {cert_path}")