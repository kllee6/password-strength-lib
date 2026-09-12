"""Pure functions for estimating password strength.

Nothing in this module reads files, touches the network, or keeps
state between calls. Every function's output depends only on its
arguments, which is what makes it easy to throw a few thousand
random strings at it in a test and trust the result.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .common_passwords import COMMON_PASSWORDS

# Rows of a standard US keyboard layout, used to catch "asdf"-style
# walks that look randomish by character-class mix but are typed by
# dragging a finger sideways.
_KEYBOARD_ROWS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
)

# Rough size of each character class, used to estimate the size of the
# alphabet an attacker would have to search. These are approximations,
# not exact counts of printable ASCII punctuation.
_CLASS_SIZES = {
    "lower": 26,
    "upper": 26,
    "digit": 10,
    "symbol": 33,
    "space": 1,
    "other": 32,
}


def char_classes(password: str) -> frozenset[str]:
    """Which character classes appear in the password."""
    classes = set()
    for ch in password:
        if ch.islower():
            classes.add("lower")
        elif ch.isupper():
            classes.add("upper")
        elif ch.isdigit():
            classes.add("digit")
        elif ch.isspace():
            classes.add("space")
        elif ch.isprintable():
            classes.add("symbol")
        else:
            classes.add("other")
    return frozenset(classes)


def charset_size(password: str) -> int:
    """Estimated size of the alphabet the password draws from."""
    return sum(_CLASS_SIZES[c] for c in char_classes(password))


def estimate_entropy_bits(password: str) -> float:
    """Rough entropy estimate: length times log2 of the alphabet size.

    This treats the password as if every character were chosen
    independently and uniformly at random, which overstates the
    entropy of anything with a recognizable pattern. score() applies
    penalties on top of this for exactly that reason.
    """
    if not password:
        return 0.0
    size = charset_size(password)
    if size <= 1:
        return 0.0
    return len(password) * math.log2(size)


def longest_sequential_run(password: str) -> int:
    """Length of the longest run of consecutive ascending or descending
    code points, e.g. "abcd" or "4321" both score 4."""
    if len(password) < 2:
        return len(password)
    longest = 1
    current = 1
    for prev, curr in zip(password, password[1:]):
        if ord(curr) - ord(prev) in (1, -1):
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


def longest_repeated_run(password: str) -> int:
    """Length of the longest run of one character repeated, e.g. "aaa" is 3."""
    if not password:
        return 0
    longest = 1
    current = 1
    for prev, curr in zip(password, password[1:]):
        if curr == prev:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


def contains_keyboard_walk(password: str, min_run: int = 4) -> bool:
    """Whether the password contains a run from a keyboard row, forwards
    or backwards, e.g. "qwer" or "trewq"."""
    lowered = password.lower()
    for row in _KEYBOARD_ROWS:
        for start in range(len(row) - min_run + 1):
            chunk = row[start : start + min_run]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def is_common_password(password: str) -> bool:
    """Whether the password (case-insensitively) is in the built-in
    list of frequently reused passwords."""
    return password.lower() in COMMON_PASSWORDS


@dataclass(frozen=True)
class StrengthResult:
    score: int  # 0 (weak) through 4 (strong)
    entropy_bits: float
    length: int
    char_classes: frozenset[str]
    warnings: tuple[str, ...]


def score(password: str) -> StrengthResult:
    """Score a password from 0 (weak) to 4 (strong).

    This combines a raw entropy estimate with penalties for patterns
    that make a password easier to guess than its entropy suggests:
    known-common passwords, repeated characters, sequential runs, and
    keyboard walks.
    """
    if not password:
        return StrengthResult(0, 0.0, 0, frozenset(), ("empty password",))

    warnings = []
    length = len(password)
    classes = char_classes(password)
    entropy = estimate_entropy_bits(password)
    common = is_common_password(password)

    if common:
        warnings.append("one of the most commonly used passwords")
    if longest_repeated_run(password) >= 3:
        warnings.append("contains a long run of the same character")
    if longest_sequential_run(password) >= 4:
        warnings.append("contains a sequential run of characters, e.g. abcd or 4321")
    if contains_keyboard_walk(password):
        warnings.append("contains a keyboard walk, e.g. qwerty or asdf")
    if length < 8:
        warnings.append("shorter than 8 characters")

    if entropy < 28:
        base = 0
    elif entropy < 36:
        base = 1
    elif entropy < 60:
        base = 2
    elif entropy < 80:
        base = 3
    else:
        base = 4

    if common:
        # a common password is weak regardless of how long or varied it looks
        penalty = 4
    elif len(warnings) >= 2:
        penalty = 1
    else:
        penalty = 0

    final_score = max(0, base - penalty)
    return StrengthResult(final_score, entropy, length, classes, tuple(warnings))
