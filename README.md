# CyberAudit

A Python CLI security audit toolkit with no external dependencies. Analyzes password strength, scans log files for threats, and verifies file integrity using SHA-256/MD5/SHA-512.

## Features

- **Password Analyzer** — entropy scoring, common password detection, keyboard-walk detection, character variety checks
- **Password Generator** — cryptographically secure passwords using Python's `secrets` module
- **Log Scanner** — regex-based detection of SSH brute-force attacks, invalid users, HTTP errors, and sudo failures
- **File Integrity Checker** — SHA-256/MD5/SHA-512 hashing with optional verification against an expected hash

## Usage

```bash
# Analyze a password
python audit.py password "MyP@ssw0rd"

# Generate a strong password (default 16 chars)
python audit.py generate --length 20

# Scan a log file for threats
python audit.py logs /var/log/auth.log

# Hash a file
python audit.py hash --file report.pdf

# Hash and verify integrity
python audit.py hash --file report.pdf --verify <expected-sha256>
```

## Example Output

```
Password Analysis
  Password : ************ (12 chars)
  Entropy  : 71.4 bits
  Score    : 30/100
  Rating   : Weak

  Issues:
    x Matches a commonly used password
    x No uppercase letters
    x No special characters
```

```
Log Security Report - auth.log (45,231 lines)
  WARNING: 3 brute-force IPs
    192.168.1.105    247 failed attempts
    10.0.0.88        134 failed attempts
    203.0.113.42      89 failed attempts

  Top Targeted Usernames
    root               312 failures
    admin               89 failures
```

## Concepts Demonstrated

- Shannon entropy calculation for password strength scoring
- Cryptographically secure random generation (`secrets` module)
- Regex-based log parsing for security threat detection
- Brute-force IP identification (threshold: 10+ failures)
- File integrity verification using `hashlib`
- Argparse subcommand CLI architecture

## Requirements

Python 3.8+. No external libraries required.

```bash
python audit.py --help
```

## Author

Jon Atakuzi — CS + Cybersecurity Minor, Mercer University (May 2026)
