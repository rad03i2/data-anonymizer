# Security Policy

## Supported version
Security fixes target the latest release on `main`.

## Data and secrets
Data Anonymizer runs locally and does not transmit input data. HMAC keys should be supplied through an environment variable, never committed to source control. Output remains potentially sensitive: masking, redaction, generalization, and pseudonymization do **not** guarantee legal or statistical anonymization for every dataset.

Do not use a short or guessable HMAC key. Rotate keys according to your organization's policy. A changed key intentionally produces different pseudonyms.

## Reporting
Please open a GitHub security advisory for vulnerabilities when possible. Avoid posting real personal data, credentials, or exploitable secrets in public issues.
