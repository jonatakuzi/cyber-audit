# CyberAudit

A Python CLI security audit toolkit — no external dependencies, no configuration files. Analyze passwords, scan log files for intrusion attempts, and verify file integrity, all from one command.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Password Analyzer** — entropy scoring, common password detection, keyboard-walk detection, character variety checks
- **Password Generator** — cryptographically secure passwords via Python's `secrets` module
- **Log Scanner** — regex-based detection of SSH brute-force attempts, invalid login users, HTTP errors (4xx/5xx), and `sudo` failures
- **File Integrity Checker** — SHA-256/MD5/SHA-512 hashing with optional verification against an expected hash
- **Directory Scanner** — hash every file in a directory and save a manifest for later comparison

All checks use Python's standard library only: `hashlib`, `secrets`, `re`, `argparse`.

## Requirements

- Python 3.7+
- No `pip install` needed

## Installation

```bash
git clone https://github.com/jonatakuzi/cyber-audit.git
cd cyber-audit
```

## Usage

### Analyze a password
```bash
python audit.py password "MyP@ssw0rd"
```
```
Score: 72/100 — Strong
✓ Length: 12 characters
✓ Uppercase, lowercase, digits, symbols
✗ Contains dictionary word pattern
```

### Generate a secure password
```bash
python audit.py generate --length 20
```

### Scan a log file for threats
```bash
python audit.py logs /var/log/auth.log
```
```
[THREAT] SSH brute-force: 47 failed attempts from 192.168.1.105
[THREAT] Invalid user "admin" attempted login 12 times
[OK] No sudo failures detected
```

### Hash a file
```bash
python audit.py hash --file report.pdf
python audit.py hash --file report.pdf --verify <expected-hash>
```

### Scan a directory and save a manifest
```bash
python audit.py scan --dir /var/www/html
```

## Tech Stack

- Python 3.7+
- Standard library: `hashlib`, `secrets`, `re`, `argparse`, `os`
