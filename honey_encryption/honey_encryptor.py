import random
from faker import Faker

faker = Faker()

def honey_encrypt(real_data, key=None, decoy_count=100):
    """
    Generate a large number of decoy passwords and insert the real one randomly.
    :param real_data: Actual password
    :param key: (Optional) encryption key (not used here, placeholder for future)
    :param decoy_count: Number of fake passwords to generate
    :return: dict with list of 'encrypted' passwords and 'key_index'
    """
    decoys = [faker.password() for _ in range(decoy_count)]
    index = random.randint(0, decoy_count)
    decoys.insert(index, real_data)
    return {
        'encrypted': decoys,
        'key_index': index
    }

def honey_decrypt(encrypted_data, key_attempt):
    """
    Retrieve a password using a guessed index.
    Returns real password only if correct index is guessed.
    :param encrypted_data: dict with encrypted list + key_index
    :param key_attempt: int index guess by user/attacker
    :return: password or fake
    """
    try:
        return encrypted_data['encrypted'][int(key_attempt)]
    except Exception:
        return "Fake Data"
