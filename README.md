PKI Management System
This project provides a set of Python scripts to manage a Public Key Infrastructure (PKI) for creating, issuing, analyzing, verifying, and revoking certificates, specifically for the bcorporation.net domain. The scripts use the cryptography library to handle certificate operations and follow standard PKI practices.
Prerequisites

Python: Version 3.6 or higher
Dependencies: Install required libraries using:pip install cryptography


Operating System: Scripts assume a Windows environment with paths like C:\PKI\. Modify paths for other operating systems as needed.

Directory Structure
The project assumes the following directory structure under C:\PKI\:

C:\PKI\ca\: Stores the Root CA certificate (root_ca.crt).
C:\PKI\keys\: Stores private keys (root_ca.key, bcorp.key).
C:\PKI\certs\: Stores issued certificates (bcorp.crt) and analysis files (bcorp_analysis.txt, bcorp_verify.txt).
C:\PKI\csr\: Stores Certificate Signing Requests (bcorp.csr).
C:\PKI\crl\: Stores Certificate Revocation Lists (root_ca.crl) and CRL analysis (bcorp_crl.txt).

Scripts and Usage
1. create_root_ca.py
Purpose: Generates a Root Certificate Authority (CA) private key and self-signed certificate.
Usage:
python create_root_ca.py

Output:

Creates directories: C:\PKI\ca\, C:\PKI\keys\, C:\PKI\certs\, C:\PKI\csr\, C:\PKI\crl\.
Saves Root CA private key to C:\PKI\keys\root_ca.key.
Saves Root CA certificate to C:\PKI\ca\root_ca.crt.

2. generate_user_csr.py
Purpose: Generates a private key and Certificate Signing Request (CSR) for bcorporation.net.
Usage:
python generate_user_csr.py

Output:

Saves private key to C:\PKI\keys\bcorp.key.
Saves CSR to C:\PKI\csr\bcorp.csr.

3. ra_process.py
Purpose: Issues a certificate for bcorporation.net based on a provided CSR after validating an authorized user ID.
Usage:
python ra_process.py C:\PKI\csr\bcorp.csr bcorp

Output:

Saves issued certificate to C:\PKI\certs\bcorp.crt.
Requires root_ca.key and root_ca.crt in their respective directories.

4. analyze_cert.py
Purpose: Downloads and analyzes the SSL certificate from bcorporation.net.
Usage:
python analyze_cert.py

Output:

Saves the downloaded certificate to C:\PKI\certs\bcorp.crt.
Saves certificate analysis (issuer, subject, serial number, validity, extensions) to C:\PKI\certs\bcorp_analysis.txt.

Note: Requires an active connection to bcorporation.net:443.
5. verify_website.py
Purpose: Verifies the bcorporation.net certificate for domain, key usage, extended key usage, issuer chain, validity period, and revocation status.
Usage:
python verify_website.py

Output:

Saves verification results to C:\PKI\certs\bcorp_verify.txt.
Saves CRL check results to C:\PKI\crl\bcorp_crl.txt.
Requires bcorp.crt, root_ca.crt, and root_ca.crl in their respective directories.

6. create_crl.py
Purpose: Creates and publishes a Certificate Revocation List (CRL), revoking the bcorporation.net certificate if it exists.
Usage:
python create_crl.py

Output:

Saves the CRL to C:\PKI\crl\root_ca.crl.
Requires root_ca.key, root_ca.crt, and optionally bcorp.crt.

Workflow

Set up Root CA:
Run create_root_ca.py to generate the Root CA key and certificate.


Generate CSR:
Run generate_user_csr.py to create a private key and CSR for bcorporation.net.


Issue Certificate:
Run ra_process.py with the CSR path and user ID (bcorp) to issue a certificate.


Analyze Certificate:
Run analyze_cert.py to download and analyze the certificate from bcorporation.net.


Verify Certificate:
Run verify_website.py to verify the certificate's properties and revocation status.


Revoke Certificate:
Run create_crl.py to generate a CRL revoking the bcorporation.net certificate.



Notes

Error Handling: Each script includes basic error handling for file operations and certificate processing. Check console output for errors.
Security: Store private keys (root_ca.key, bcorp.key) securely and restrict access.
Customization: Modify paths, validity periods, or certificate attributes as needed.
Dependencies: Ensure cryptography is installed, and verify internet access for analyze_cert.py.

Example Execution
python create_root_ca.py
python generate_user_csr.py
python ra_process.py C:\PKI\csr\bcorp.csr bcorp
python analyze_cert.py
python verify_website.py
python create_crl.py
