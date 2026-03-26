from honey_encryption.honey_encryptor import honey_encrypt, honey_decrypt

# Simulate storing a password
real_password = "myS3cr3tPass!"
key = "42"  # just symbolic for now

encrypted = honey_encrypt(real_password, key)
print("Encrypted data (with decoys):", encrypted)

# Try to decrypt with the correct index
correct_index = encrypted['key_index']
print("\nTrying correct index:", correct_index)
print("Decrypted:", honey_decrypt(encrypted, correct_index))

# Try to decrypt with wrong index
wrong_index = (correct_index + 1) % len(encrypted['encrypted'])
print("\nTrying wrong index:", wrong_index)
print("Decrypted:", honey_decrypt(encrypted, wrong_index))
