import hashlib
import requests
import string
import math
import argparse
import logging
import csv
import os
import datetime
import random

# -----------------------------
# Logging Setup
# -----------------------------
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# -----------------------------
# Password Strength (rule-based)
# -----------------------------
def password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = sum([has_upper, has_lower, has_digit, has_symbol])

    if length < 8:
        return "Weak"
    elif score < 4:
        return "Moderate"
    else:
        return "Strong"

# -----------------------------
# Entropy Calculation
# -----------------------------
def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += 32

    return round(len(password) * math.log2(charset), 2) if charset else 0

# -----------------------------
# Breach Check (HIBP API)
# -----------------------------
def is_password_breached(password):
    sha1pwd = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            logging.error("HIBP API error")
            return False, 0
    except:
        logging.error("Network error contacting HIBP")
        return False, 0

    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return True, int(count)
    return False, 0

# -----------------------------
# Secure Hash for Reports
# -----------------------------
def hash_for_report(password):
    return hashlib.sha256(password.encode()).hexdigest()

# -----------------------------
# Password Generator
# -----------------------------
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))

# -----------------------------
# CSV Export
# -----------------------------
def export_csv(results):
    filename = "logs/security_report.csv"
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Password Hash",
            "Strength",
            "Entropy",
            "Breached",
            "Breach Count"
        ])
        for r in results:
            writer.writerow(r)
    print(f"\n✅ Report exported to {filename}")

# -----------------------------
# Analyze Password
# -----------------------------
def analyze_password(password, check_breach=True):
    strength = password_strength(password)
    entropy = calculate_entropy(password)

    breached, count = (False, 0)
    if check_breach:
        breached, count = is_password_breached(password)

    if strength == "Weak" or breached:
        logging.warning("Security issue detected")

    return (
        hash_for_report(password),
        strength,
        entropy,
        breached,
        count
    )

# -----------------------------
# Summary Report
# -----------------------------
def print_summary(results):
    total = len(results)
    weak = sum(1 for r in results if r[1] == "Weak")
    breached = sum(1 for r in results if r[3])
    avg_entropy = round(sum(r[2] for r in results) / total, 2) if total else 0

    print("\n=== Security Analysis Summary ===")
    print(f"Passwords analyzed: {total}")
    print(f"Weak passwords: {weak}")
    print(f"Breached passwords: {breached}")
    print(f"Average entropy: {avg_entropy} bits")

# -----------------------------
# File Scanner
# -----------------------------
def analyze_file(filepath, check_breach):
    if not os.path.exists(filepath):
        print("File not found")
        return

    results = []
    with open(filepath, "r") as f:
        for line in f:
            password = line.strip()
            if password:
                results.append(analyze_password(password, check_breach))

    export_csv(results)
    print_summary(results)

# -----------------------------
# Interactive Mode
# -----------------------------
def interactive_mode(check_breach):
    results = []

    while True:
        password = input("\nEnter password (or type exit): ")
        if password.lower() == "exit":
            break

        result = analyze_password(password, check_breach)
        results.append(result)

        print(f"Strength: {result[1]}")
        print(f"Entropy: {result[2]} bits")

        if result[3]:
            print(f"⚠ Breached {result[4]} times")
        else:
            print("✅ Not found in breaches")

        if result[1] != "Strong":
            print("💡 Suggested password:", generate_password())

    if results:
        export_csv(results)
        print_summary(results)

# -----------------------------
# CLI Arguments
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Password Security Analyzer")
    parser.add_argument("--generate", type=int, help="Generate strong password")
    parser.add_argument("--check-file", help="Analyze passwords from file")
    parser.add_argument("--no-breach-check", action="store_true")

    args = parser.parse_args()

    if args.generate:
        print("Generated password:", generate_password(args.generate))
        return

    check_breach = not args.no_breach_check

    if args.check_file:
        analyze_file(args.check_file, check_breach)
    else:
        interactive_mode(check_breach)

if __name__ == "__main__":
    main()
