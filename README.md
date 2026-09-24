# password-strength-lib

Most "password strength" checks are either a length-only regex or a
call out to some third-party scoring service. This is a small,
dependency-free Python library that scores a password locally using
a few plain heuristics: an entropy estimate based on the character
classes used, plus penalties for patterns that make a password
weaker than its raw entropy suggests (repeated characters, sequential
runs like `abcd`, keyboard walks like `qwerty`, dates like `1990` or
`03-15-1990`, and membership in a list of commonly reused passwords).

Every public function is pure: same input, same output, no I/O, no
hidden state. That makes it straightforward to unit test and safe to
call from request handlers, CLIs, or batch jobs without worrying
about side effects.

## Usage

```python
from password_strength import score

result = score("Tr0ub4dour&9xQ!lm")
print(result.score)          # 0-4, higher is stronger
print(result.entropy_bits)   # rough entropy estimate in bits
print(result.warnings)       # tuple of human-readable reasons for the score
```

```python
from password_strength import score

for candidate in ["password", "abc123", "qwerty1234", "Tr0ub4dour&9xQ!lm"]:
    result = score(candidate)
    print(f"{candidate!r}: score={result.score} entropy={result.entropy_bits:.1f} bits")
```

The individual heuristics are also exposed directly, in case you want
to build your own scoring policy instead of using `score()`:

```python
from password_strength import (
    char_classes,
    contains_date_pattern,
    contains_keyboard_walk,
    estimate_entropy_bits,
    is_common_password,
    longest_repeated_run,
    longest_sequential_run,
)

char_classes("Ab1!")              # frozenset({'upper', 'lower', 'digit', 'symbol'})
estimate_entropy_bits("Ab1!cdef") # bits, assuming uniform random selection
longest_sequential_run("x9abcdy") # 4, for the "abcd" run
longest_repeated_run("aaabbc")    # 3, for the "aaa" run
contains_keyboard_walk("myqwerty1") # True
contains_date_pattern("mypass1990")  # True, reads as a birth year
contains_date_pattern("03-15-1990")  # True, reads as a full date
is_common_password("Password1")   # True (checked case-insensitively)
```

`score()` returns a `StrengthResult`, a frozen dataclass with
`score`, `entropy_bits`, `length`, `char_classes`, and `warnings`
fields, so callers can render whatever UI they want from the same
data rather than parsing a string.

## What this is not

The entropy estimate assumes characters are drawn independently and
uniformly at random, which is generous for anything with a
recognizable structure (a word plus a digit, a name and a year, and
so on). The pattern checks catch some of the most common ways real
passwords fall short of that assumption, but this is not a
replacement for a proper breach-corpus check like a k-anonymity
lookup against Have I Been Pwned. The common-password list shipped
here is a curated sample of the passwords that repeatedly top
published breach analyses, not a full corpus import, so it will
still miss plenty of passwords that a real k-anonymity lookup would
catch.

## Installation

This is not published to PyPI yet. Clone the repository and install
it locally:

```
pip install -e .
```

It has no runtime dependencies beyond the Python standard library.

## Running the tests

```
python -m unittest discover tests
```

## License

MIT, see [LICENSE](LICENSE).
