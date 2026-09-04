"""
Custom HMAC (Hash-based Message Authentication Code)

HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
  K'   = key, zero-padded/hashed to match the hash's block size
  ipad = 0x36 repeated
  opad = 0x5c repeated
  H    = SHA-256

Used for:
  - Signing session tokens (integrity + tamper detection)
  - Generating HMAC-based OTP codes for 2FA
  - MAC tags on diary entries (requirement #7)
"""

import hashlib
import hmac as _hmac_compare  # constant-time comparison only, not used for the HMAC computation

BLOCK_SIZE = 64  # SHA-256 block size in bytes
DIGEST_SIZE = 32  # SHA-256 output size in bytes

IPAD = 0x36
OPAD = 0x5c


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _prepare_key(key: bytes) -> bytes:
    """Pad or hash the key down to exactly BLOCK_SIZE bytes."""
    if len(key) > BLOCK_SIZE:
        key = _sha256(key)
    return key + b'\x00' * (BLOCK_SIZE - len(key))


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256(key, message) from scratch. Returns raw bytes."""
    key = _prepare_key(key)

    inner_pad = bytes(b ^ IPAD for b in key)
    outer_pad = bytes(b ^ OPAD for b in key)

    inner_hash = _sha256(inner_pad + message)
    return _sha256(outer_pad + inner_hash)


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    return hmac_sha256(key, message).hex()


def verify_hmac(key: bytes, message: bytes, tag: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    expected = hmac_sha256(key, message)
    return _hmac_compare.compare_digest(expected, tag)


if __name__ == "__main__":
    # self-test against a known RFC 4231 test vector for HMAC-SHA256
    key = b"\x0b" * 20
    data = b"Hi There"
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

    result = hmac_sha256_hex(key, data)
    print("Computed :", result)
    print("Expected :", expected)
    print("Match    :", result == expected)
