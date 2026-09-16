"""
Verhoeff Checksum Algorithm Implementation.

Aadhaar numbers are 12-digit identification numbers where the 12th digit
is a checksum calculated using the Verhoeff algorithm over the dihedral group D5.
It catches 100% of single-digit errors and >95% of adjacent transposition errors.
"""

# The multiplication table (Dihedral group D5)
_D_TABLE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

# The permutation table
_P_TABLE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

# The inverse table
_INV_TABLE = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def validate_verhoeff(number: str) -> bool:
    """Validate whether the given numeric string satisfies the Verhoeff checksum."""
    clean = "".join(filter(str.isdigit, str(number)))
    if not clean:
        return False

    c = 0
    reversed_digits = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        c = _D_TABLE[c][_P_TABLE[i % 8][digit]]
    return c == 0


def is_valid_aadhaar(aadhaar: str) -> bool:
    """Validate a 12-digit Aadhaar number per UIDAI specifications."""
    clean = "".join(filter(str.isdigit, str(aadhaar)))
    if len(clean) != 12:
        return False
    # Aadhaar specification forbids starting with 0 or 1
    if clean[0] in ("0", "1"):
        return False
    return validate_verhoeff(clean)
