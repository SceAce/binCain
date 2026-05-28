from __future__ import annotations

import string

_ALPHABET = string.ascii_lowercase.encode()
_SUBSEQUENCE_LENGTH = 4


def cyclic(length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    return _de_bruijn(_ALPHABET, _SUBSEQUENCE_LENGTH)[:length]


def cyclic_find(value: bytes | bytearray | int, *, width: int | None = None, max_length: int = 8192) -> int | None:
    if isinstance(value, int):
        if width is None:
            width = 8
        if width <= 0:
            raise ValueError("width must be positive")
        needle = value.to_bytes(width, "little", signed=False)
    else:
        needle = bytes(value)

    if not needle:
        return None
    offset = cyclic(max_length).find(needle)
    return offset if offset >= 0 else None


def _de_bruijn(alphabet: bytes, subsequence_length: int) -> bytes:
    k = len(alphabet)
    a = [0] * (k * subsequence_length)
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > subsequence_length:
            if subsequence_length % p == 0:
                sequence.extend(a[1 : p + 1])
            return
        a[t] = a[t - p]
        db(t + 1, p)
        for j in range(a[t - p] + 1, k):
            a[t] = j
            db(t + 1, t)

    db(1, 1)
    return bytes(alphabet[i] for i in sequence)
