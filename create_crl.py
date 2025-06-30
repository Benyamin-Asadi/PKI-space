# create_crl.py
# Creates and publishes CRL, revoking bcorporation.net certificate

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
import datetime
import os

# Load Root CA key and certificate
with open(r"C:\PKI\keys\root_ca.key", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)
with open(r"C:\PKI\ca\root_ca.crt", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Create CRL
crl = x509.CertificateRevocationListBuilder().issuer_name(
    ca_cert.subject
).last_update(
    datetime.datetime.utcnow()
).next_update(
    datetime.datetime.utcnow() + datetime.timedelta(days=30)
)

# Revoke bcorporation.net certificate if it exists
bcorp_cert_path = r"C:\PKI\certs\bcorp.crt"
if os.path.exists(bcorp_cert_path):
    with open(bcorp_cert_path, "rb") as f:
        bcorp_cert = x509.load_pem_x509_certificate(f.read())
    crl = crl.add_revoked_certificate(
        x509.RevokedCertificateBuilder().serial_number(
            bcorp_cert.serial_number
        ).revocation_date(
            datetime.datetime.utcnow()
        ).build()
    )

# Sign and save CRL
crl = crl.sign(ca_key, hashes.SHA256())
crl_path = r"C:\PKI\crl\root_ca.crl"
with open(crl_path, "wb") as f:
    f.write(crl.public_bytes(serialization.Encoding.PEM))

print(f"CRL published at {crl_path}, revoking bcorporation.net certificate if present")