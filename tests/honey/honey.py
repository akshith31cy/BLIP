# tests/honey/honey.py
import os
import json
import base64
import hashlib
import hmac
import secrets
from faker import Faker

faker = Faker()

def _hmac_index(key: str, salt: bytes, n: int) -> int:
    """Return deterministic index in [0, n-1] based on key+salt."""
    hm = hmac.new(key.encode(), salt, hashlib.sha256).digest()
    # turn first 8 bytes into an int
    idx = int.from_bytes(hm[:8], "big") % n
    return idx

def encrypt(real_key: str, encoded_plaintext: str, decoy_count: int = 6):
    """
    Create a honey-encrypted object:
      - random salt
      - decoy_count decoys (strings that are DTE-encoded)
      - real encoded plaintext placed at position determined by HMAC(real_key, salt)
    Returns a dict (serializable) representing the cipher.
    """
    salt = secrets.token_bytes(16)
    decoys = []
    for _ in range(decoy_count):
        # generate plausible-looking fake JSON strings (or random passwords)
        # We produce base64-encoded strings so they can be fed to DTE.decode safely
        fake_obj = {"fake_secret": faker.password(length=10)}
        fake_encoded = base64.b64encode(json.dumps(fake_obj).encode()).decode()
        decoys.append(fake_encoded)

    n = len(decoys)
    # determine index from real_key and salt
    idx = _hmac_index(real_key, salt, n)
    # insert the real encoded plaintext at idx (replace decoy)
    decoys[idx] = encoded_plaintext

    cipher = {
        "salt": base64.b64encode(salt).decode(),
        "decoys": decoys,
        # (do not store real index — attacker shouldn't know)
    }
    return cipher

def decrypt(key_attempt: str, cipher: dict):
    """
    Given a key attempt and the cipher dict, return the encoded item chosen
    by HMAC(key_attempt, salt) mod n.
    """
    salt = base64.b64decode(cipher["salt"].encode())
    decoys = cipher["decoys"]
    n = len(decoys)
    idx = _hmac_index(key_attempt, salt, n)
    return decoys[idx]

class DTE:
    """
    Very small deterministic encoder/decoder used in examples.
    Here we just base64-encode the JSON so it survives transmission.
    """
    @staticmethod
    def encode(s: str) -> str:
        # Expect s as a str (json dumps for objects)
        return base64.b64encode(s.encode()).decode()

    @staticmethod
    def decode(b64: str) -> str:
        try:
            return base64.b64decode(b64.encode()).decode()
        except Exception:
            return ""
