"""
ecc_custom.py
Elliptic Curve Cryptography implemented: EC-ElGamal scheme.

Why EC-ElGamal (not "ECDH + AES" style ECIES)?
  The project forbids symmetric encryption entirely. Standard ECIES derives
  a shared secret via ECDH and then encrypts the actual message with a
  symmetric cipher (AES/ChaCha) — that would break the "asymmetric only"
  rule. EC-ElGamal instead embeds the message directly as a POINT on the
  curve and encrypts it using only point arithmetic — genuinely asymmetric
  end-to-end, the elliptic-curve equivalent of RSA's textbook encryption.

Curve: secp256k1 (the same curve Bitcoin uses). Its domain parameters
(p, a, b, G, n) are public standard constants — not a crypto library import,
just numbers, the same way Lab7 used y^2 = x^3 - 2x + 2 (mod 23) as public
curve constants. All point addition, doubling, scalar multiplication,
encoding, encryption and decryption below are implemented by us.
"""

import os

# ---------- secp256k1 domain parameters (public constants) ----------
P = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
A = 0
B = 7
Gx = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
Gy = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
G = (Gx, Gy)
N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141

K_EMBED = 1000  # embedding factor for Koblitz's method — bigger = safer, slower


# ---------- modular helpers ----------

def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def _mod_inverse(a, m):
    a = a % m
    gcd, x, _ = _extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("No modular inverse exists")
    return x % m


def _mod_sqrt(a, p):
    """Modular square root for p ≡ 3 (mod 4), which secp256k1's p satisfies.
    Returns None if a has no square root mod p."""
    if pow(a, (p - 1) // 2, p) != 1:
        return None  # a is not a quadratic residue
    return pow(a, (p + 1) // 4, p)


# ---------- elliptic curve point arithmetic ----------

IDENTITY = None  # point at infinity


def point_add(P1, P2):
    if P1 is IDENTITY:
        return P2
    if P2 is IDENTITY:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % P == 0:
        return IDENTITY  # P + (-P) = infinity

    if P1 == P2:
        m = (3 * x1 * x1 + A) * _mod_inverse(2 * y1, P) % P
    else:
        m = (y2 - y1) * _mod_inverse(x2 - x1, P) % P

    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    """Double-and-add scalar multiplication: k * point."""
    result = IDENTITY
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def point_negate(point):
    if point is IDENTITY:
        return IDENTITY
    x, y = point
    return (x, (-y) % P)


# ---------- key generation ----------

def generate_keys():
    """Returns (public_key_point, private_key_int)."""
    d = int.from_bytes(os.urandom(32), 'big') % (N - 1) + 1
    Q = scalar_mult(d, G)
    return Q, d


# ---------- message <-> point encoding (Koblitz's method) ----------

def _encode_chunk_to_point(m: int):
    """Embed integer m as a curve point via Koblitz's method (trial x-values)."""
    for j in range(K_EMBED):
        x = m * K_EMBED + j
        if x >= P:
            raise ValueError("Chunk too large to embed")
        rhs = (x ** 3 + A * x + B) % P
        y = _mod_sqrt(rhs, P)
        if y is not None:
            return (x, y)
    raise ValueError("Failed to embed message chunk as a curve point")


def _decode_point_to_chunk(point) -> int:
    x, _ = point
    return x // K_EMBED


def _chunk_byte_size() -> int:
    """How many bytes of plaintext fit in one embeddable chunk."""
    # m must satisfy m * K_EMBED < P, leave a safety margin
    max_m_bits = P.bit_length() - K_EMBED.bit_length() - 8
    return max_m_bits // 8


# ---------- EC-ElGamal encryption / decryption ----------

def encrypt_text(plaintext: str, public_key_point):
    """Encrypt a string. Returns a list of (C1, C2) point pairs, one per chunk."""
    data = plaintext.encode('utf-8')
    size = _chunk_byte_size()
    chunks = [data[i:i + size] for i in range(0, len(data), size)]

    ciphertext = []
    for chunk in chunks:
        m = int.from_bytes(chunk, 'big')
        M = _encode_chunk_to_point(m)

        k = int.from_bytes(os.urandom(32), 'big') % (N - 1) + 1
        C1 = scalar_mult(k, G)
        C2 = point_add(M, scalar_mult(k, public_key_point))
        ciphertext.append((C1, C2))
    return ciphertext


def decrypt_text(ciphertext, private_key: int) -> str:
    """Decrypt a list of (C1, C2) point pairs back into the original string."""
    size = _chunk_byte_size()
    plaintext_bytes = b''

    for C1, C2 in ciphertext:
        shared = scalar_mult(private_key, C1)
        M = point_add(C2, point_negate(shared))
        m = _decode_point_to_chunk(M)
        chunk = m.to_bytes(size, 'big').lstrip(b'\x00')
        plaintext_bytes += chunk
    return plaintext_bytes.decode('utf-8')


if __name__ == "__main__":
    print("Generating ECC keypair...")
    public_key, private_key = generate_keys()
    print("Public key point:", public_key)
    print("Private key:", private_key)

    message = "Dear diary, today was a good day."
    print("\nOriginal:", message)

    ct = encrypt_text(message, public_key)
    print("Encrypted (chunks):", len(ct), "point-pairs")

    pt = decrypt_text(ct, private_key)
    print("Decrypted:", pt)
    print("Match:", pt == message)
