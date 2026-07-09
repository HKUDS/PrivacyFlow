from __future__ import annotations

import re


PEM_RE = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]+?-----END \1-----")


def pem_pair_valid(value: str) -> bool:
    return bool(PEM_RE.fullmatch(value.strip()))
