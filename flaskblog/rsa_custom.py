"""
rsa_custom.py
RSA implemented from scratch (based on the standard textbook algorithm,
following the same structure used in Lab6 and the GeeksforGeeks reference
the group started from).

Fixes over the toy GfG version:
  - Uses large random primes (not 7919/1009) — real RSA needs primes
    hundreds of bits long or it's trivially breakable.
  - modInverse uses the Extended Euclidean Algorithm instead of brute-force
    "hit and trial" — brute force would never finish with real-sized primes.
  - Adds text <-> integer chunking so arbitrary-length strings (emails,
    usernames, diary text) can be encrypted, not just one small integer.

sympy is used ONLY for prime generation/testing (same as Lab6) — it is not
an encryption library. All RSA math (keygen, encrypt, decrypt) is our own.
"""

import random
import sympy


# ----------- core RSA math -----------

def _power(base, expo, m):
    """Fast modular exponentiation: base^expo mod m."""
    res = 1
    base = base % m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo //= 2
    return res


def _extended_gcd(a, b):
    """Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def _mod_inverse(e, phi):
    """Find d such that (e * d) % phi == 1, using Extended Euclidean Algorithm."""
    gcd, x, _ = _extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("e and phi(n) are not coprime — no inverse exists")
    return x % phi


def generate_keys(bits: int = 512):
    """Generate an RSA keypair. Returns (public_key, private_key) as ((e, n), (d, n))."""
    p = sympy.randprime(2 ** (bits - 1), 2 ** bits - 1)
    q = sympy.randprime(2 ** (bits - 1), 2 ** bits - 1)
    while p == q:
        q = sympy.randprime(2 ** (bits - 1), 2 ** bits - 1)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # standard choice, small and works for almost all phi values
    if sympy.gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)
        while sympy.gcd(e, phi) != 1:
            e = random.randrange(3, phi, 2)

    d = _mod_inverse(e, phi)

    return (e, n), (d, n)


# ---------- text <-> integer chunking ----------

def _chunk_size(n: int) -> int:
    """Max number of bytes we can safely pack under n per block."""
    byte_len = (n.bit_length() // 8) - 1  # leave 1 byte of headroom
    return max(byte_len, 1)


def encrypt_text(plaintext: str, public_key) -> list:
    """Encrypt a string, returns a list of ciphertext integers (one per chunk)."""
    e, n = public_key
    data = plaintext.encode('utf-8')
    size = _chunk_size(n)

    chunks = [data[i:i + size] for i in range(0, len(data), size)]
    ciphertext = []
    for chunk in chunks:
        m = int.from_bytes(chunk, 'big')
        c = _power(m, e, n)
        ciphertext.append(c)
    return ciphertext


def decrypt_text(ciphertext: list, private_key) -> str:
    """Decrypt a list of ciphertext integers back into the original string."""
    d, n = private_key
    size = _chunk_size(n)

    plaintext_bytes = b''
    for c in ciphertext:
        m = _power(c, d, n)
        chunk = m.to_bytes(size, 'big').lstrip(b'\x00')
        plaintext_bytes += chunk
        # note: lstrip on the padding zero byte works because we encrypt
        # each chunk independently and chunk length <= size
    return plaintext_bytes.decode('utf-8')


if __name__ == "__main__":
    print("Generating RSA keypair (this takes a moment)...")
    public_key, private_key = generate_keys(bits=512)
    print("Public key (e, n):", public_key)
    print("Private key (d, n):", private_key)

    message = "user@example.com"
    print("\nOriginal:", message)

    ct = encrypt_text(message, public_key)
    print("Encrypted (chunks):", ct)

    pt = decrypt_text(ct, private_key)
    print("Decrypted:", pt)
    print("Match:", pt == message)
