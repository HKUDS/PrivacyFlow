from __future__ import annotations

import re


def luhn_valid(candidate: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", candidate)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0
