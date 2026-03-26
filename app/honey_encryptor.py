# app/honey_encryptor.py
import random
import string
from .hash_algorithms import hash_password

COMMON_SUFFIXES = ["123", "!", "2023", "2024", "pass", "@"]
COMMON_WORDS = ["password", "welcome", "admin", "user", "login", "qwerty"]

def mutate_password(pw: str) -> str:
    # some simple mutations: append suffix, swap chars, substitute letters
    w = pw
    ops = [
        lambda s: s + random.choice(COMMON_SUFFIXES),
        lambda s: s[::-1],
        lambda s: s + ''.join(random.choices(string.digits, k=2)),
        lambda s: s.replace('a', '@').replace('o', '0'),
        lambda s: s.capitalize(),
        lambda s: s + random.choice(COMMON_WORDS)
    ]
    op = random.choice(ops)
    return op(w)[:64]

def generate_decoys(real_pw: str, count: int = 9):
    """
    Return tuple (honey_hashes_list, real_index)
    - honey_hashes_list length = count + 1 (includes real password hashed)
    - real_index is index of real password within list
    """
    if count < 3:
        count = 3
    decoy_plain = set()
    # create decoys by mutation
    while len(decoy_plain) < count:
        decoy_plain.add(mutate_password(real_pw))
    # also add some common words
    while len(decoy_plain) < count + 1:
        decoy_plain.add(random.choice(COMMON_WORDS) + random.choice(COMMON_SUFFIXES))

    decoy_plain = list(decoy_plain)
    # insert the real password as well
    decoy_plain.append(real_pw)
    random.shuffle(decoy_plain)
    # hash all
    honey_hashes = [hash_password(p) for p in decoy_plain]
    real_index = decoy_plain.index(real_pw)
    return honey_hashes, real_index
