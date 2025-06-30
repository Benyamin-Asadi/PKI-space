# verify_website.py
# Verifies bcorporation.net certificate for domain and server use

import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime
import sys

# Ensure output directories exist
os.makedirs(r"C:\PKI\certs", exist_ok=True)
os.makedirs(r"C:\PKI\crl", exist_ok=True)

# Load bcorporation.net certificate
cert_path = r"C:\PKI\certs\bcorp.crt"
try:
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
except FileNotFoundError:
    print(f"Error: Certificate file not found at {cert_path}")
    print("Run ra_process.py to generate bcorp.crt")
    sys.exit(1)
except Exception as e:
    print(f"Error loading certificate from {cert_path}: {e}")
    sys.exit(1)

# Load Root CA certificate
root_cert_path = r"C:\PKI\ca\root_ca.crt"
try:
    with open(root_cert_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
except Exception as e:
    print(f"Error loading root certificate from {root_cert_path}: {e}")
    sys.exit(1)

# Verify certificate
verify_path = r"C:\PKI\certs\bcorp_verify.txt"
try:
    with open(verify_path, "w", encoding="utf-8") as f:
        # Check SAN for bcorporation.net
        san_valid = False
        for ext in cert.extensions:
            if ext.oid._name == "subjectAlternativeName":
                san = ext.value
                for name in san:
                    if isinstance(name, x509.DNSName) and name.value == "bcorporation.net":
                        san_valid = True
                        f.write("SAN matches bcorporation.net.\n")
                        break
                if not san_valid:
                    f.write("SAN does not include bcorporation.net.\n")
                break
        else:
            f.write("No SAN extension found.\n")

        # Check KeyUsage
        key_usage_valid = False
        for ext in cert.extensions:
            if ext.oid._name == "keyUsage":
                ku = ext.value
                if ku.digital_signature and ku.key_encipherment:
                    key_usage_valid = True
                    f.write("KeyUsage includes digitalSignature and keyEncipherment.\n")
                else:
                    f.write("KeyUsage missing required values (digitalSignature, keyEncipherment).\n")
                break
        else:
            f.write("No KeyUsage extension found.\n")

        # Check ExtendedKeyUsage
        eku_valid = False
        for ext in cert.extensions:
            if ext.oid._name == "extendedKeyUsage":
                eku = ext.value
                if ExtendedKeyUsageOID.SERVER_AUTH in eku:
                    eku_valid = True
                    f.write("ExtendedKeyUsage includes serverAuth.\n")
                else:
                    f.write("ExtendedKeyUsage missing serverAuth.\n")
                break
        else:
            f.write("No ExtendedKeyUsage extension found.\n")

        # Check issuer or authority key identifier
        if cert.issuer == root_cert.subject or any(ext.oid._name == "authorityKeyIdentifier" for ext in cert.extensions):
            f.write("Certificate chain appears valid (issuer matches root or has AKI).\n")
        else:
            f.write("Certificate chain verification failed: issuer does not match root.\n")

        # Check validity 
        now = datetime.datetime.now(datetime.timezone.utc)
        if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            f.write("Certificate is within validity period.\n")
        else:
            f.write("Certificate is expired or not yet valid.\n")

except Exception as e:
    print(f"Error writing verification results to {verify_path}: {e}")
    sys.exit(1)

# Check CRL
crl_path = r"C:\PKI\crl\root_ca.crl"
crl_analysis_path = r"C:\PKI\crl\bcorp_crl.txt"
try:
    with open(crl_path, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())
    with open(crl_analysis_path, "w", encoding="utf-8") as f:
        revoked = False
        for revoked_cert in crl:
            if revoked_cert.serial_number == cert.serial_number:
                f.write("Certificate is revoked.\n")
                revoked = True
                break
        if not revoked:
            f.write("Certificate is not revoked.\n")
except Exception as e:
    print(f"Error processing CRL: {e}")
    with open(crl_analysis_path, "w", encoding="utf-8") as f:
        f.write(f"CRL check failed: {e}\n")

print(f"Verification results in {verify_path} and CRL analysis in {crl_analysis_path}")