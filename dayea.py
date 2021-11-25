from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode

# Primary reference: 
# https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2
# Note: it's a starred medium article!
class AESCipher:
    def __init__(self, password):
        self.block_size = 16
        self.key = self.__derive_key(password)
        self.filepath = 'test.bin'
    
    def __derive_key(self, password):

        # ideally, the salt should be random and
        # do not rely with the password, but since
        # this would only have a single master pass
        # then this would do for now

        hasher = SHA256.new(data=password.encode())
        salt = hasher.digest()

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
    
    def encrypt(self, plaintext):
        nonce, ciphertext, tag = self.__encrypt(plaintext)
        with open(self.filepath, 'wb') as f:
            [f.write(x) for x in (nonce, tag, ciphertext)]
    
    def decrypt(self):
        with open(self.filepath, 'rb') as f:
            nonce, tag, ciphertext = [ f.read(x) for x in (self.block_size, self.block_size, -1) ]
        data = self.__decrypt(nonce, ciphertext, tag)
        return data

if __name__ == '__main__':
    print("ENCRYPT PASSWORD? (Y/N)")
    if input().upper() == 'Y':
        print("ENTER MASTER PASSWORD:")
        password = input()
        print("ENTER PASSWORD:")
        plaintext = input()

        dayea = AESCipher(password)
        dayea.encrypt(plaintext)
    else:
        print("ENTER MASTER PASSWORD:")
        password = input()

        dayea = AESCipher(password)
        print(dayea.decrypt())