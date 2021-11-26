import os
import dotenv
from dotenv import load_dotenv
from base64 import b64encode, b64decode
from io import BytesIO
import json

from Crypto import Random
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


# Primary reference: 
# https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2
# Note: it's a starred medium article!
class Dayea:
    """
    An AES Cipher class
    """

    def __init__(self, password):
        self.block_size = 16
        self.key = self.__derive_key(password)
        self.filepath = 'test.bin'
    
    def __derive_key(self, password):

        try:
            b64_salt = os.environ['MASTER-SALT']
            # convert to bytes
            salt = b64decode(b64_salt)
        except KeyError as e:
            salt = Random.get_random_bytes(self.block_size)
            # convert to string
            b64_salt = b64encode(salt)
            # update environment variable
            os.environ['MASTER-SALT'] = b64_salt.decode('utf-8')
            dotenv.set_key('.env', 'MASTER-SALT', os.environ['MASTER-SALT'])
            
        # N, r, p are based on the following lecture:
        # http://www.tarsnap.com/scrypt/scrypt-slides.pdf
        key = scrypt(password, salt, self.block_size, N=2**20, r=8, p=1)
        return key
    
    def __pad(self, plaintext):
        number_of_bytes_to_pad = self.block_size - len(plaintext) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plaintext = plaintext + padding_str
        return padded_plaintext
    
    @staticmethod
    def __unpad(plaintext):
        last_character = plaintext[-1]
        bytes_to_remove = ord(last_character)
        return plaintext[:-bytes_to_remove]
    
    def __encrypt(self, plaintext):
        data = self.__pad(plaintext)
        cipher = AES.new(self.key, AES.MODE_EAX)

        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return nonce, ciphertext, tag
    
    def __decrypt(self, nonce, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        plaintext = self.__unpad(data)
        return plaintext
    
    def encrypt(self, plaintext : str) -> bytes:
        nonce, ciphertext, tag = self.__encrypt(plaintext)
        raw_binary = BytesIO()
        [raw_binary.write(x) for x in (nonce, tag, ciphertext)]
        encoded_binary = b64encode(raw_binary.getvalue())
        return encoded_binary

    def decrypt(self, encoded_binary : bytes) -> str:
        encoded_binary = BytesIO(encoded_binary)
        raw_binary = BytesIO(b64decode(encoded_binary.getvalue()))
        nonce, tag, ciphertext = [ raw_binary.read(x) for x in (self.block_size, self.block_size, -1) ]
        data = self.__decrypt(nonce, ciphertext, tag)
        return data
    
    def add_account(self, site, username, password):

        encoded_password = self.encrypt(password)
        with open('test.json', 'a+') as db_file:
            try:
                db = json.load(db_file)
            except Exception:
                db = { }
            
            if not site in db.keys():
                db[site] = { }
            try:
                db[site][username] = encoded_password.decode('utf-8')
            except KeyError:
                db[site] = { username : encoded_password.decode('utf-8') }
            
            print(db)
            json.dump(db, db_file)
    
    def get_accounts(self):

        with open('test.json') as db_file:
            try:
                db = json.load(db_file)
            except Exception as e:
                print(e)
                db = { }
            
        for site, site_accounts in db.items():
            for account, encoded_password in site_accounts.items():
                yield (site, account, self.decrypt(encoded_password.encode('utf-8')))

if __name__ == '__main__':
    load_dotenv()

    master = input("Enter master password: ")
    dayea = Dayea(master)

    while input("Continue? (Y/N): ").upper() == 'Y':
        mode = int(input("What do you want to do? (1) Add account or (2) Memorize passwords?: "))
        if mode == 1:
            site = input("Enter site name: ")
            username = input("Enter username/email: ")
            password = input("Enter your password (be careful of people snooping): ")
            dayea.add_account(site, username, password)
        elif mode == 2:
            for site, username, password in dayea.get_accounts():
                print("Enter password for: ", site, username)
                for i in range(3):
                    attempt = input()
                    if attempt == password:
                        print("Correct!")
                        break
                    else:
                        print(f"Wrong. {3-i-1} attempts left...")
            