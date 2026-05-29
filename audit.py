"""
audit.py - Python CLI security audit toolkit. No external dependencies.

Commands:
    password <pw>          -- Score password strength and give improvement tips
    generate               -- Generate a cryptographically secure random password
    logs <file>            -- Scan a log file for security threats (SSH, HTTP, sudo)
    hash --file <path>     -- Compute SHA-256/MD5/SHA-512 hash of a file
    scan --dir <path>      -- Hash every file in a directory and save a manifest

All checks use Python's standard library only (hashlib, secrets, re, argparse).

Usage:
    python audit.py password "MyP@ssw0rd"
    python audit.py generate --length 20
    python audit.py logs /var/log/auth.log
    python audit.py hash --file report.pdf --verify <expected-hash>
    python audit.py scan --dir /etc --output manifest.txt
"""

import argparse
import hashlib
import math
import os
import re
import secrets
import string
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# Password strength analysis
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "password1", "qwerty", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine",
    "iloveyou", "admin", "login", "passw0rd", "abc123",
}

KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qweasd", "123456",
    "654321", "abcdef",
]


def calc_entropy(password: str) -> float:
    """
    Estimate the Shannon entropy of a password in bits.
    Higher entropy means more unpredictability. We determine the character
    pool size based on which character classes appear in the password,
    then apply: entropy = length * log2(pool_size).
    A score above 60 bits is generally considered strong.
    """
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def score_password(password: str) -> dict:
    """
    Run a multi-factor strength analysis on a password and return a score dict.

    Checks performed:
      - Length (min 8, ideally 12+)
      - Character variety (uppercase, lowercase, digits, symbols)
      - Entropy estimate in bits
      - Common password list membership
      - Keyboard walk patterns (e.g. 'qwerty', 'asdfg')

    Returns a dict with 'score' (0-100), 'rating' string, and 'tips' list.
    """
    tips = []
    score = 0

    # Length
    if len(password) >= 16:
        score += 30
    elif len(password) >= 12:
        score += 20
    elif len(password) >= 8:
        score += 10
    else:
        tips.append("Use at least 8 characters (12+ is much stronger).")

    # Character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10

    if not has_upper:
        tips.append("Add uppercase letters.")
    if not has_digit:
        tips.append("Add numbers.")
    if not has_symbol:
        tips.append("Add symbols like !@#$.")

    # Entropy bonus
    entropy = calc_entropy(password)
    if entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 10

    # Common password penalty
    if password.lower() in COMMON_PASSWORDS:
        score -= 40
        tips.append("This is a commonly used password. Change it immediately.")

    # Keyboard walk penalty
    pw_lower = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in pw_lower:
            score -= 15
            tips.append(f"Avoid keyboard patterns like '{walk}'.")
            break

    score = max(0, min(100, score))

    if score >= 80:
        rating = "Strong"
    elif score >= 50:
        rating = "Moderate"
    elif score >= 25:
        rating = "Weak"
    else:
        rating = "Very Weak"

    return {"score": score, "rating": rating, "entropy_bits": round(entropy, 1), "tips": tips}


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    """
    Generate a cryptographically secure random password using Python's secrets module.
    The secrets module is designed for security-sensitive applications and is
    significantly stronger than random.choice(), which is NOT suitable for passwords.
    We guarantee at least one character from each required class to satisfy
    most site password policies.
    """
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += string.punctuation

    # Guarantee at least one from each class
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        required.append(secrets.choice(string.punctuation))

    remaining = [secrets.choice(chars) for _ in range(length - len(required))]
    pool = required + remaining
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


# ---------------------------------------------------------------------------
# Log threat scanner
# ---------------------------------------------------------------------------

THREAT_PATTERNS = [
    (r"Failed password for (?:invalid user )?(S+) from ([d.]+)", "SSH failed login"),
    (r"Invalid user (S+) from ([d.]+)", "SSH invalid user"),
    (r"authentication failure.*user=(S+)", "Auth failure"),
    (r"FAILED su for (S+) by (S+)", "Failed su attempt"),
    (r"sudo:.*FAILED", "Sudo failure"),
    (r"HTTP/d.d["\s]+(?:4d{2}|5d{2})", "HTTP 4xx/5xx error"),
    (r"([d.]+) .* "(?:GET|POST|PUT|DELETE) .*" 40[13]", "HTTP 401/403 forbidden"),
]


def scan_logs(filepath: str) -> list[dict]:
    """
    Scan a log file line by line and match against known threat signatures.

    Each pattern targets a specific attack type:
      - SSH failed logins and invalid users (brute-force indicators)
      - Auth failures and failed sudo (privilege escalation attempts)
      - HTTP 4xx/5xx errors (web scanning or unauthorized access)

    Returns a list of dicts with 'line_num', 'threat_type', and 'line' for
    every matched line. Useful for quickly finding the signal in noisy logs.
    """
    findings = []
    try:
        with open(filepath, "r", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.rstrip()
                for pattern, threat_type in THREAT_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "line_num": line_num,
                            "threat_type": threat_type,
                            "line": line[:200],
                        })
                        break
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    return findings


# ---------------------------------------------------------------------------
# File integrity / hashing
# ---------------------------------------------------------------------------

def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """
    Compute the cryptographic hash of a file using the specified algorithm.
    We read the file in 64KB chunks to handle large files without loading
    everything into memory at once. Supported: sha256, md5, sha512.
    SHA-256 is the default because it balances speed and collision resistance.
    """
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        print(f"Unsupported algorithm: {algorithm}. Use sha256, md5, or sha512.")
        sys.exit(1)

    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    return h.hexdigest()


# ---------------------------------------------------------------------------
# Directory scan / integrity manifest
# ---------------------------------------------------------------------------

def scan_directory(directory: str, algorithm: str = "sha256") -> list[dict]:
    """
    Recursively hash every file in a directory tree.
    Returns a list of dicts with 'path', 'algorithm', and 'hash' for each file.

    This builds a file integrity manifest — a snapshot of every file's hash
    at a point in time. If you run this again later and compare the results,
    any changed hash means the file was modified. This is the foundation of
    intrusion detection systems like Tripwire.
    """
    results = []
    directory = os.path.abspath(directory)

    if not os.path.isdir(directory):
        print(f"Error: Not a directory: {directory}", file=sys.stderr)
        sys.exit(1)

    for root, _, files in os.walk(directory):
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            try:
                file_hash = hash_file(filepath, algorithm)
                results.append({
                    "path": filepath,
                    "algorithm": algorithm,
                    "hash": file_hash,
                })
            except Exception:
                results.append({
                    "path": filepath,
                    "algorithm": algorithm,
                    "hash": "ERROR",
                })

    return results


# ---------------------------------------------------------------------------
# CLI command handlers
# ---------------------------------------------------------------------------

def cmd_password(args, _) -> None:
    """
    Analyze a password and print a detailed strength report.
    The score is 0-100 and considers length, character variety,
    entropy, common passwords, and keyboard patterns.
    """
    result = score_password(args.password)
    print(f"\nPassword Analysis")
    print("-" * 40)
    print(f"Score:       {result['score']}/100")
    print(f"Rating:      {result['rating']}")
    print(f"Entropy:     {result['entropy_bits']} bits")

    if result["tips"]:
        print("\nSuggestions:")
        for tip in result["tips"]:
            print(f"  - {tip}")
    else:
        print("\nNo major issues found.")
    print()


def cmd_generate(args, _) -> None:
    """
    Generate a secure random password and display its strength score.
    Uses Python's secrets module, which is backed by the OS random source.
    """
    pw = generate_password(length=args.length, use_symbols=not args.no_symbols)
    result = score_password(pw)
    print(f"\nGenerated Password: {pw}")
    print(f"Strength: {result['rating']} ({result['score']}/100, {result['entropy_bits']} bits entropy)")
    print()


def cmd_logs(args, _) -> None:
    """
    Scan a log file for security threats and print a summary.
    Matches lines against patterns for SSH attacks, auth failures,
    sudo failures, and HTTP errors. Prints up to 20 findings to avoid
    flooding the terminal on noisy log files.
    """
    findings = scan_logs(args.file)

    print(f"\nLog Scan: {args.file}")
    print("-" * 60)

    if not findings:
        print("No threats detected.")
        print()
        return

    print(f"Found {len(findings)} potential threat(s):\n")
    for f in findings[:20]:
        print(f"  Line {f['line_num']:>5}  [{f['threat_type']}]")
        print(f"           {f['line'][:100]}")
        print()

    if len(findings) > 20:
        print(f"  ... and {len(findings) - 20} more. Run with --export to save all findings.")


def cmd_hash(args, _) -> None:
    """
    Hash a file and optionally verify it against an expected hash.
    Useful for checking that a downloaded file or backup has not been tampered with.
    The --verify flag compares your stored hash against what we compute now.
    """
    alg = args.algorithm.lower()
    digest = hash_file(args.file, alg)

    print(f"\nFile: {args.file}")
    print(f"Algorithm: {alg.upper()}")
    print(f"Hash: {digest}")

    if args.verify:
        if digest.lower() == args.verify.lower():
            print("Verification: PASS - hashes match")
        else:
            print("Verification: FAIL - hashes do NOT match")
            sys.exit(1)
    print()


def cmd_scan(args, _) -> None:
    """
    Recursively hash every file in a directory and write a manifest file.
    The manifest records each file path and its hash so you can re-run
    the scan later and diff the results to detect any unauthorized changes.
    Think of it as a lightweight version of what tools like Tripwire do.
    """
    alg = args.algorithm.lower()
    results = scan_directory(args.dir, alg)

    output = args.output or f"manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(output, "w") as f:
        f.write(f"# Integrity Manifest\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Directory: {os.path.abspath(args.dir)}\n")
        f.write(f"# Algorithm: {alg.upper()}\n")
        f.write(f"# Files: {len(results)}\n\n")
        for entry in results:
            f.write(f"{entry['hash']}  {entry['path']}\n")

    print(f"\nScanned {len(results)} file(s) in '{args.dir}'")
    print(f"Manifest saved to: {output}")
    print(f"Algorithm: {alg.upper()}")
    print()


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Wire up the argument parser with subcommands.
    Each subcommand maps to one cmd_* function, keeping them easy to extend.
    """
    parser = argparse.ArgumentParser(
        prog="audit",
        description="Python CLI security audit toolkit — no external dependencies.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # password
    p_pw = sub.add_parser("password", help="Analyze password strength")
    p_pw.add_argument("password", help="The password to analyze")

    # generate
    p_gen = sub.add_parser("generate", help="Generate a secure random password")
    p_gen.add_argument("--length", type=int, default=16, help="Password length (default 16)")
    p_gen.add_argument("--no-symbols", action="store_true", help="Omit special characters")

    # logs
    p_logs = sub.add_parser("logs", help="Scan a log file for security threats")
    p_logs.add_argument("file", help="Path to log file")

    # hash
    p_hash = sub.add_parser("hash", help="Hash a file and optionally verify it")
    p_hash.add_argument("--file", required=True, help="File to hash")
    p_hash.add_argument("--algorithm", default="sha256", choices=["sha256", "md5", "sha512"])
    p_hash.add_argument("--verify", help="Expected hash to compare against")

    # scan
    p_scan = sub.add_parser("scan", help="Hash all files in a directory (integrity manifest)")
    p_scan.add_argument("--dir", required=True, help="Directory to scan")
    p_scan.add_argument("--algorithm", default="sha256", choices=["sha256", "md5", "sha512"])
    p_scan.add_argument("--output", help="Output manifest file (default: manifest_<timestamp>.txt)")

    return parser


COMMANDS = {
    "password": cmd_password,
    "generate": cmd_generate,
    "logs": cmd_logs,
    "hash": cmd_hash,
    "scan": cmd_scan,
}


def main():
    """Parse arguments and dispatch to the correct command handler."""
    parser = build_parser()
    args = parser.parse_args()
    COMMANDS[args.command](args, None)


if __name__ == "__main__":
    main()
