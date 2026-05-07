"""Password hashing and validation.

Uses the ``bcrypt`` library directly. ``passlib[bcrypt]`` is in requirements
to keep bcrypt as a transitive dep, but passlib 1.7.4 has a known startup
incompatibility with bcrypt 4.x (its wrap-bug detection trips bcrypt's new
72-byte limit), so we call bcrypt directly.
"""

from __future__ import annotations
import re
import secrets
import string

import bcrypt

# Cost factor 12 — meets the >= 12 requirement, ~250ms per verify on
# typical hardware. Bumping is the right knob if hardware speeds up.
_BCRYPT_ROUNDS = 12

# bcrypt has a 72-byte input limit. We reject longer passwords at the
# validation step instead of silently truncating them.
_MAX_PASSWORD_BYTES = 72


class PasswordValidationError(ValueError):
    pass


_RE_UPPER = re.compile(r"[A-Z]")
_RE_DIGIT = re.compile(r"[0-9]")
# Anything that isn't a letter, digit, or whitespace counts as a special char.
_RE_SPECIAL = re.compile(r"[^A-Za-z0-9\s]")


def validate_password(password: str) -> None:
    """Raises PasswordValidationError on the first rule failure."""
    if not isinstance(password, str):
        raise PasswordValidationError("Password must be a string")
    if len(password) < 12:
        raise PasswordValidationError("Password must be at least 12 characters")
    if len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        raise PasswordValidationError(
            f"Password must be at most {_MAX_PASSWORD_BYTES} bytes"
        )
    if not _RE_UPPER.search(password):
        raise PasswordValidationError("Password must contain an uppercase letter")
    if not _RE_DIGIT.search(password):
        raise PasswordValidationError("Password must contain a number")
    if not _RE_SPECIAL.search(password):
        raise PasswordValidationError("Password must contain a special character")


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def hash_token(raw_token: str) -> str:
    """Bcrypt hash for opaque high-entropy tokens (e.g. refresh tokens).

    Refresh tokens come in as 128-char hex strings — over bcrypt's 72-byte
    input limit. We pre-digest with SHA-256 to get a fixed 64-byte input.
    The token's entropy already exceeds bcrypt's brute-force resistance
    bound, so the work factor exists only to slow down a stolen-DB scan.
    """
    import hashlib

    digest = hashlib.sha256(raw_token.encode("utf-8")).digest()
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(digest, salt).decode("utf-8")


def verify_token(raw_token: str, token_hash: str) -> bool:
    if not token_hash or not raw_token:
        return False
    import hashlib

    try:
        digest = hashlib.sha256(raw_token.encode("utf-8")).digest()
        return bcrypt.checkpw(digest, token_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def generate_temporary_password() -> str:
    """Generate a 16-char password that satisfies the validation rules."""
    alphabet_lower = string.ascii_lowercase
    alphabet_upper = string.ascii_uppercase
    digits = string.digits
    specials = "!@#$%^&*()-_=+"
    pool = alphabet_lower + alphabet_upper + digits + specials

    chars = [
        secrets.choice(alphabet_upper),
        secrets.choice(digits),
        secrets.choice(specials),
        secrets.choice(alphabet_lower),
    ]
    chars += [secrets.choice(pool) for _ in range(12)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
