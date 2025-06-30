# generate_bcorp_csr.py
# Generates private key and CSR for bcorporation.net

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import os

# Generate private key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key_path = r"C:\PKI\keys\bcorp.key"
with open(key_path, "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Generate CSR with SAN for bcorporation.net
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "B Corporation"),
    x509.NameAttribute(NameOID.COMMON_NAME, "bcorporation.net")
])).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("bcorporation.net")]),
    critical=False
).sign(key, hashes.SHA256())

# Save CSR
csr_path = r"C:\PKI\csr\bcorp.csr"
with open(csr_path, "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

print(f"CSR for bcorporation.net created at {csr_path}")