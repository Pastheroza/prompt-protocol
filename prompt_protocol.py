import hashlib
import unicodedata
import re
import logging
from typing import Optional

__version__ = "0.2.5"

# Logger setup (app controls level)
logger = logging.getLogger(__name__)

# Custom exceptions per spec error codes
class PPError(Exception):
    """Base PP exception"""
    pass

class PPEmptyInputError(PPError):
    """ERR_EMPTY_INPUT"""
    pass

class PPChecksumInvalidError(PPError):
    """ERR_CHECKSUM_INVALID"""
    pass

# Crockford Base32 alphabet (excludes I, L, O, U)
CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
CROCKFORD_MAP = {char: i for i, char in enumerate(CROCKFORD_ALPHABET)}

# Masks for GF(2^n) reduction
masks = (3, 3, 3, 5, 3, 3, 27, 3, 9, 5, 9, 27, 33, 3, 43, 9,
         9, 39, 9, 5, 3, 33, 27, 9, 27, 39, 3, 5, 3, 9, 141)

def damm_interim(digits: list[int], n: int = 5) -> int:
    """Compute Damm interim (running checksum)"""
    modulus = (1 << n)
    mask = modulus | masks[n - 2]
    checksum = 0
    for digit in digits:
        checksum ^= digit
        checksum <<= 1
        if checksum >= modulus:
            checksum ^= mask
        checksum &= (modulus - 1)
    return checksum

def damm_checksum(id_digits: list[int], n: int = 5) -> str:
    """Generate Damm check digit"""
    interim = damm_interim(id_digits)
    modulus = (1 << n)
    mask = modulus | masks[n - 2]
    for d in range(modulus):
        check = interim ^ d
        check <<= 1
        if check >= modulus:
            check ^= mask
        check &= (modulus - 1)
        if check == 0:
            return CROCKFORD_ALPHABET[d]
    raise PPError("No valid check digit found")

def normalize_crockford(s: str) -> str:
    """Normalize Crockford input (handle I/L→1, O→0, upper)"""
    return s.upper().replace('I', '1').replace('L', '1').replace('O', '0')

def validate_pp_code(id_encoded: str, check_char: str) -> bool:
    """Validate PP-code (with Crockford normalization)"""
    logger.debug(f"Validating PP-code: {id_encoded}-{check_char}")
    id_encoded_norm = normalize_crockford(id_encoded)
    check_char_norm = normalize_crockford(check_char)
    id_digits = [CROCKFORD_MAP.get(c, -1) for c in id_encoded_norm]
    if -1 in id_digits:
        logger.warning("Invalid characters in ID")
        raise PPChecksumInvalidError("Invalid characters in ID")
    check_digit = CROCKFORD_MAP.get(check_char_norm, -1)
    if check_digit == -1:
        logger.warning("Invalid check character")
        raise PPChecksumInvalidError("Invalid check character")
    full_digits = id_digits + [check_digit]
    if damm_interim(full_digits) != 0:
        raise PPChecksumInvalidError("Checksum validation failed")
    return True

def normalize_text(text: str) -> bytes:
    """Normalize text per spec: trim (with BOM) → line endings → NFC"""
    logger.debug("Normalizing text")
    # Trim leading/trailing whitespace + BOM
    text = re.sub(r'^[\s\uFEFF]+|[\s\uFEFF]+$', '', text)
    # Line endings to LF
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    # NFC normalization
    text = unicodedata.normalize('NFC', text)
    normalized_bytes = text.encode('utf-8')
    if not normalized_bytes:
        logger.warning("Empty prompt after normalization")
        raise PPEmptyInputError("Empty prompt after normalization")
    return normalized_bytes

def compute_sha256(data: bytes) -> bytes:
    """Compute SHA-256"""
    return hashlib.sha256(data).digest()

def extract_bits(hash_bytes: bytes, bits: int = 50) -> int:
    """Extract first 'bits' bits as integer (big-endian)"""
    byte_len = (bits + 7) // 8
    extracted = hash_bytes[:byte_len]
    int_val = int.from_bytes(extracted, 'big')
    extra_bits = byte_len * 8 - bits
    if extra_bits > 0:
        int_val >>= extra_bits
    return int_val

def crockford_base32_encode(value: int, length: int = 10) -> str:
    """Encode to Crockford Base32"""
    result = ''
    for _ in range(length):
        value, rem = divmod(value, 32)
        result = CROCKFORD_ALPHABET[rem] + result
    return result

def generate_pp_code(text: str, bits: int = 50, group: Optional[str] = None, key: Optional[str] = None) -> str:
    """Generate full PP-code (with optional @GROUP, K:KEY)"""
    if not isinstance(text, str):
        logger.warning("Input must be a string")
        raise TypeError("Input must be a string")
    logger.debug(f"Generating PP-code for text of length {len(text)}, bits={bits}")
    normalized = normalize_text(text)
    hash_bytes = compute_sha256(normalized)
    value = extract_bits(hash_bytes, bits)
    width = bits // 5  # Auto width per bits (5 bits per char)
    id_encoded = crockford_base32_encode(value, width)
    id_digits = [CROCKFORD_MAP[c] for c in id_encoded]
    check = damm_checksum(id_digits)
    code = f"PP-{id_encoded}-{check}"
    if group:
        code += f"-@{group}"
    if key:
        code += f"-K:{key}"
    return code

# Pytest suite (separate for CI/CD, but included for single-file convenience)
try:
    import pytest
except ImportError:
    pytest = None  # Optional: if no pytest, skip tests on import

if pytest:
    @pytest.mark.parametrize("text, expected", [
        ("Hello, World!", "PP-VZYP08DV5F-M"),
        ("\ufeffHello, World! ", "PP-VZYP08DV5F-M"),  # BOM + spaces
        ("résumé", "PP-X7VVBDMPCR-X"),  # Real vector
    ])
    def test_generate_pp_code(text: str, expected: str) -> None:
        assert generate_pp_code(text) == expected

    @pytest.mark.parametrize("text, bits, expected", [
        ("Hello, World!", 60, "PP-VZYP08DV5FAV-4"),  # Real 60-bit, auto width=12
    ])
    def test_generate_extended(text: str, bits: int, expected: str) -> None:
        assert generate_pp_code(text, bits) == expected

    @pytest.mark.parametrize("id_encoded, check_char, expected_valid", [
        ("VZYP08DV5F", "M", True),
        ("VZYP08DV5F", "m", True),  # lower
        ("VZYPo8DV5F", "M", True),  # O→0
        ("VZYP08DV5F", "X", False),  # invalid
    ])
    def test_validate_pp_code(id_encoded: str, check_char: str, expected_valid: bool) -> None:
        if expected_valid:
            assert validate_pp_code(id_encoded, check_char)
        else:
            with pytest.raises(PPChecksumInvalidError):
                validate_pp_code(id_encoded, check_char)

    def test_empty_prompt() -> None:
        with pytest.raises(PPEmptyInputError):
            generate_pp_code("   \n  ")

    def test_invalid_input_type() -> None:
        with pytest.raises(TypeError):
            generate_pp_code(123)  # type: ignore

    def test_group_key() -> None:
        assert generate_pp_code("Hello, World!", group="PRAMPTA", key="A7F3") == "PP-VZYP08DV5F-M-@NASA-K:A7F3"

if __name__ == "__main__":
    if pytest:
        pytest.main([__file__, "-v"])
    else:
        print("pytest not installed; run 'pip install pytest' to test")
