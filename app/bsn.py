def is_valid_bsn(bsn: str|int) -> bool:
    """
    Check if a BSN is valid.
    """
    bsn_str = str(bsn).zfill(9)

    # A BSN must be exactly 9 digits long
    if len(bsn_str) != 9 or not bsn_str.isdigit():
        return False

    # Apply the 11-proef
    total = sum(int(digit) * (9 - idx) for idx, digit in enumerate(bsn_str[:-1]))
    total -= int(bsn_str[-1])

    return total % 11 == 0