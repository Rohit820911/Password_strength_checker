import hashlib
import json
import math
import os
import random
import re
import secrets
import string
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
COMMON_PASSWORDS_FILE = BASE_DIR / "common_passwords.txt"

app = Flask(__name__)


def load_common_passwords() -> set[str]:
    if not COMMON_PASSWORDS_FILE.exists():
        return set()
    with COMMON_PASSWORDS_FILE.open("r", encoding="utf-8") as f:
        return {
            line.strip().lower()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        }


COMMON_PASSWORDS = load_common_passwords()


def has_repeated_pattern(password: str) -> bool:
    if len(password) < 4:
        return False

    # repeated same char
    if len(set(password)) <= 2 and len(password) >= 6:
        return True

    # detect repeated chunks like abcabc, 123123, !@#!@#
    for size in range(1, max(2, len(password) // 2 + 1)):
        if len(password) % size == 0:
            chunk = password[:size]
            if chunk * (len(password) // size) == password:
                return True

    # detect repeated adjacent substrings
    for size in range(1, len(password) // 2 + 1):
        for start in range(0, len(password) - 2 * size + 1):
            first = password[start : start + size]
            second = password[start + size : start + 2 * size]
            if first == second:
                return True

    return False


def detect_charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)

    return max(size, 1)


def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    charset_size = detect_charset_size(password)
    return len(password) * math.log2(charset_size)


def human_readable_time(seconds: float) -> str:
    if seconds < 1:
        return "less than 1 second"
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    years = days / 365.25

    if seconds < 60:
        return f"{round(seconds)} seconds"
    if minutes < 60:
        return f"{round(minutes)} minutes"
    if hours < 24:
        return f"{round(hours)} hours"
    if days < 365.25:
        return f"{round(days)} days"
    return f"{round(years)} years"


def estimate_crack_times(entropy_bits: float) -> dict:
    # Expected guesses are ~ 2^(entropy - 1)
    expected_guesses = 2 ** max(entropy_bits - 1, 0)

    # Assumptions for educational simulation
    offline_rate = 10_000_000_000  # 10 billion guesses/sec
    online_rate = 100              # 100 guesses/sec

    offline_seconds = expected_guesses / offline_rate
    online_seconds = expected_guesses / online_rate

    return {
        "offline_seconds": offline_seconds,
        "online_seconds": online_seconds,
        "offline_readable": human_readable_time(offline_seconds),
        "online_readable": human_readable_time(online_seconds),
    }


def strength_score(password: str) -> tuple[int, str]:
    score = 0
    length = len(password)

    if length >= 8:
        score += 15
    if length >= 12:
        score += 15
    if length >= 16:
        score += 10

    if any(c.islower() for c in password):
        score += 10
    if any(c.isupper() for c in password):
        score += 10
    if any(c.isdigit() for c in password):
        score += 10
    if any(c in string.punctuation for c in password):
        score += 15

    if has_repeated_pattern(password):
        score -= 15

    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        score -= 40
    elif any(common in lower for common in COMMON_PASSWORDS if len(common) >= 4):
        score -= 15

    if length < 6:
        score -= 20

    score = max(0, min(100, score))

    if score < 40:
        label = "Weak"
    elif score < 75:
        label = "Medium"
    else:
        label = "Strong"

    return score, label


def build_suggestions(password: str, score: int, label: str) -> list[str]:
    suggestions = []
    length = len(password)

    if length == 0:
        return ["Start typing a password to see feedback."]

    if length < 12:
        suggestions.append("Increase length to at least 12 characters.")
    if not any(c.isupper() for c in password):
        suggestions.append("Add uppercase letters.")
    if not any(c.islower() for c in password):
        suggestions.append("Add lowercase letters.")
    if not any(c.isdigit() for c in password):
        suggestions.append("Add numbers.")
    if not any(c in string.punctuation for c in password):
        suggestions.append("Add special characters.")
    if has_repeated_pattern(password):
        suggestions.append("Avoid repeated patterns or repeated characters.")
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append("Do not use common passwords.")
    if score < 75:
        suggestions.append("Mix character types to improve strength.")

    if label == "Strong":
        suggestions = ["Good password structure. Keep it unique and private."]

    return suggestions[:6]


def analyze_password(password: str) -> dict:
    entropy = calculate_entropy(password)
    score, label = strength_score(password)
    crack_times = estimate_crack_times(entropy)

    length_ok = len(password) >= 12
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_number = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    common_hit = password.lower() in COMMON_PASSWORDS
    repeated = has_repeated_pattern(password)

    return {
        "password": password,
        "length": len(password),
        "checks": {
            "length": "Good" if length_ok else "Weak",
            "uppercase": "Yes" if has_upper else "No",
            "lowercase": "Yes" if has_lower else "No",
            "numbers": "Yes" if has_number else "No",
            "special_characters": "Yes" if has_symbol else "No",
            "repeated_patterns": "Detected" if repeated else "None",
            "common_password": "Yes" if common_hit else "No",
        },
        "score": score,
        "strength": label,
        "entropy": round(entropy, 2),
        "charset_size": detect_charset_size(password),
        "crack_time": crack_times,
        "suggestions": build_suggestions(password, score, label),
        "hashes": {
            "md5": hashlib.md5(password.encode("utf-8")).hexdigest() if password else "",
            "sha256": hashlib.sha256(password.encode("utf-8")).hexdigest() if password else "",
        },
    }


def generate_password(length: int = 16, use_upper: bool = True, use_lower: bool = True,
                      use_digits: bool = True, use_symbols: bool = True) -> str:
    length = max(8, min(int(length), 64))

    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/")

    if not pools:
        pools = [string.ascii_letters + string.digits]

    all_chars = "".join(pools)

    # guarantee at least one from each chosen group
    password_chars = [secrets.choice(pool) for pool in pools]

    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    return jsonify(analyze_password(password))


@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json(silent=True) or {}
    length = int(data.get("length", 16))
    use_upper = bool(data.get("use_upper", True))
    use_lower = bool(data.get("use_lower", True))
    use_digits = bool(data.get("use_digits", True))
    use_symbols = bool(data.get("use_symbols", True))

    password = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
    return jsonify({"password": password, "analysis": analyze_password(password)})


@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    return jsonify({
        "md5": hashlib.md5(password.encode("utf-8")).hexdigest() if password else "",
        "sha256": hashlib.sha256(password.encode("utf-8")).hexdigest() if password else "",
    })


if __name__ == "__main__":
    app.run(debug=True)
