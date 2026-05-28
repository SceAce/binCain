from bincain.cyclic import cyclic, cyclic_find


def test_cyclic_generates_stable_unique_pattern_prefix():
    assert cyclic(12) == b"aaaabaaacaaa"


def test_cyclic_find_accepts_bytes_and_little_endian_ints():
    pattern = cyclic(128)
    needle = pattern[40:44]

    assert cyclic_find(needle) == 40
    assert cyclic_find(int.from_bytes(needle, "little"), width=4) == 40
