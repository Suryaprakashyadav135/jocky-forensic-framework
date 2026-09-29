"""
JOCKY Framework — Module 4: Cryptography Layer
ECDH key exchange + HKDF derivation + AES-256-GCM encryption.
"""

import os
import base64
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


CURVE = ec.SECP256R1()
HKDF_INFO = b"JOCKY-v1-session-key"


def generate_keypair():
    """Return (private_key, public_key_bytes)."""
    priv = ec.generate_private_key(CURVE)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return priv, pub_bytes


def load_public_key(pub_bytes: bytes):
    """Reconstruct a public key from raw bytes."""
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, pub_bytes)


def derive_shared_secret(priv, peer_pub_bytes: bytes) -> bytes:
    """ECDH: compute the shared secret."""
    peer_pub = load_public_key(peer_pub_bytes)
    return priv.exchange(ec.ECDH(), peer_pub)


def derive_aes_key(shared_secret: bytes, salt: bytes = b"") -> bytes:
    """HKDF-SHA256 → 32-byte AES key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


class SecureSession:
    """
    A single encrypted session between a client and the server.
    Uses AES-256-GCM with unique nonces per message.
    """

    def __init__(self, aes_key: bytes, session_id: str = None):
        self.aes_key = aes_key
        self.aesgcm = AESGCM(aes_key)
        self.session_id = session_id or base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")
        self.counter = 0  # for replay protection

    def encrypt(self, plaintext: dict) -> str:
        """Encrypt a dict → base64 string (nonce || ciphertext)."""
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        pt = json.dumps(plaintext, separators=(",", ":")).encode()

        # Extra authenticated data: session_id + counter (prevents replay)
        aad = f"{self.session_id}:{self.counter}".encode()
        ct = self.aesgcm.encrypt(nonce, pt, aad)

        self.counter += 1
        blob = nonce + ct
        return base64.urlsafe_b64encode(blob).decode()

    def decrypt(self, b64_blob: str, expected_counter: int = None) -> dict:
        """Decrypt a base64 string → dict."""
        blob = base64.urlsafe_b64decode(b64_blob.encode())
        nonce, ct = blob[:12], blob[12:]

        # If caller specifies counter, use it (allows stateless server)
        counter = expected_counter if expected_counter is not None else self.counter
        aad = f"{self.session_id}:{counter}".encode()

        pt = self.aesgcm.decrypt(nonce, ct, aad)
        if expected_counter is None:
            self.counter += 1
        return json.loads(pt.decode())


def sha256_short(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]
