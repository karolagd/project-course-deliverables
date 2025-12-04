from cryptography.fernet import Fernet
import os

class Decryptor:
    def __init__(self):
        self.key = None
        self.crypter = None
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.localRoot = os.path.join(script_dir, 'DANGER')



    def load_key(self, key_path):
        with open(key_path, 'rb') as f:
            self.key = f.read().strip()
            self.crypter = Fernet(self.key)
            print(f'Fernet key: {self.key.decode()}')

    def decrypt_file(self, file_path):
        if not file_path.endswith('.x2anylock'):
                return
        else:

            try:
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.crypter.decrypt(encrypted_data)
                original_path = file_path.replace('.x2anylock', '')
                with open(original_path, 'wb') as f:
                    f.write(decrypted_data)
                os.remove(file_path)
                print(f'Decrypted: {file_path} → {original_path}')
            except Exception as e:
                print(f'Failed to decrypt {file_path}: {e}')

    def decrypt_system(self):
        for root, dirs, files in os.walk(self.localRoot, topdown=True):
            for file in files:
                file_path = os.path.join(root, file)
                self.decrypt_file(file_path)

def main():
    dc = Decryptor()
    dc.load_key(f'{dc.localRoot}/YOUR_KEY.txt')
    dc.decrypt_system()
    print('Files decrypted.')

if __name__ == '__main__':
    main()
