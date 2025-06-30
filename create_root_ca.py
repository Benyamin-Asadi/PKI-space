# create_root_ca.py
# Creates Root CA key and certificate

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import os

# Create directories
os.makedirs(r"C:\PKI\ca", exist_ok=True)
os.makedirs(r"C:\PKI\keys", exist_ok=True)
os.makedirs(r"C:\PKI\certs", exist_ok=True)
os.makedirs(r"C:\PKI\csr", exist_ok=True)
os.makedirs(r"C:\PKI\crl", exist_ok=True)

# Generate Root CA private key
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
key_path = r"C:\PKI\keys\root_ca.key"
with open(key_path, "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Create Root CA certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT"),
    x509.NameAttribute(NameOID.COMMON_NAME, "RootCA")
])
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True
).sign(key, hashes.SHA256())

# Save Root CA certificate
cert_path = r"C:\PKI\ca\root_ca.crt"
with open(cert_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"Root CA created at {cert_path}")