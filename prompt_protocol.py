import hashlib
import unicodedata
import re

# Crockford Base32 alphabet (excludes I, L, O, U to avoid confusion)
CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
CROCKFORD_MAP = {char: i for i, char in enumerate(CROCKFORD_ALPHABET)}

# Masks for GF(2^n) reduction (running checksum)
masks = (3, 3, 3, 5, 3, 3, 27, 3, 9, 5, 9, 27, 33, 3, 43, 9,
         9, 39, 9, 5, 3, 33, 27, 9, 27, 39, 3, 5, 3, 9, 141)

# Compute Damm interim (running checksum)
def damm_interim(digits, n=5):
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

# Generate Damm check digit
def damm_checksum(id_digits, n=5):
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
    raise ValueError("No valid check digit found")

# Normalize Crockford input (handle I/L→1, O→0, upper)
def normalize_crockford(s):
    return s.upper().replace('I', '1').replace('L', '1').replace('O', '0')

# Validate PP-code (with Crockford normalization)
def validate_pp_code(id_encoded, check_char):
    id_encoded_norm = normalize_crockford(id_encoded)
    check_char_norm = normalize_crockford(check_char)
    id_digits = [CROCKFORD_MAP.get(c, -1) for c in id_encoded_norm]
    if -1 in id_digits:
        return False
    check_digit = CROCKFORD_MAP.get(check_char_norm, -1)
    if check_digit == -1:
        return False
    full_digits = id_digits + [check_digit]
    return damm_interim(full_digits) == 0

# Normalize text per spec: trim (with BOM) → line endings → NFC
def normalize_text(text):
    # Trim leading/trailing whitespace + BOM
    text = re.sub(r'^[\s\uFEFF]+|[\s\uFEFF]+$', '', text)
    # Line endings to LF
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    # NFC normalization
    text = unicodedata.normalize('NFC', text)
    return text.encode('utf-8')

# Compute SHA-256
def compute_sha256(data):
    return hashlib.sha256(data).digest()

# Extract first 'bits' bits as integer (big-endian)
def extract_bits(hash_bytes, bits=50):
    byte_len = (bits + 7) // 8
    extracted = hash_bytes[:byte_len]
    int_val = int.from_bytes(extracted, 'big')
    extra_bits = byte_len * 8 - bits
    if extra_bits > 0:
        int_val >>= extra_bits
    return int_val

# Encode to Crockford Base32
def crockford_base32_encode(value, length=10):
    result = ''
    for _ in range(length):
        value, rem = divmod(value, 32)
        result = CROCKFORD_ALPHABET[rem] + result
    return result

# Generate full PP-code (without optional @GROUP or K:KEY)
def generate_pp_code(text, bits=50, min_width=10):
    normalized = normalize_text(text)
    hash_bytes = compute_sha256(normalized)
    value = extract_bits(hash_bytes, bits)
    id_encoded = crockford_base32_encode(value, min_width)
    id_digits = [CROCKFORD_MAP[c] for c in id_encoded]
    check = damm_checksum(id_digits)
    return f"PP-{id_encoded}-{check}"

# Example verification
if __name__ == "__main__":
    test_text = "Hello, World!"
    pp_code = generate_pp_code(test_text)
    print(f"Generated PP-code for '{test_text}': {pp_code}")
    
    # Validate (standard)
    id_part, check_part = pp_code.split('-')[1], pp_code.split('-')[2]
    is_valid = validate_pp_code(id_part, check_part)
    print(f"Validation: {'Valid' if is_valid else 'Invalid'}")
    
    # Validate with errors (O instead of 0, lower case)
    is_valid_mixed = validate_pp_code('VZYP08DV5F', 'm')  # lower m
    print(f"Validation mixed case: {'Valid' if is_valid_mixed else 'Invalid'}")
    is_valid_o = validate_pp_code('VZYPo8DV5F', 'M')  # O instead of 0
    print(f"Validation with O: {'Valid' if is_valid_o else 'Invalid'}")
    
    # Extended (60 bits)
    pp_code_extended = generate_pp_code(test_text, bits=60, min_width=12)
    print(f"Extended (60 bits): {pp_code_extended}")

    # Test with BOM
    bom_text = "\ufeffHello, World! "
    pp_code_bom = generate_pp_code(bom_text)
    print(f"With BOM and spaces: {pp_code_bom}")