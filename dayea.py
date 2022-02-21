from dis import Instruction
from email.charset import QP
import os
import dotenv
import sys
from dotenv import load_dotenv
from base64 import b64encode, b64decode
from io import BytesIO
import json
import datetime as dt
from datetime import datetime
from datetime import date
from collections import deque

import random
import string

from Crypto import Random
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QLabel,
    QWidget,
    QGridLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout, 
    QHBoxLayout,
)

# Primary reference: 
# https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2
# Note: it's a starred medium article!
class Dayea:
    """
    An AES Cipher class
    """

    def __init__(self, password : str, filepath : str):
        self.block_size = 16
        self.key = self.__derive_key(password)
        self.filepath = filepath
    
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
        try:
            with open(self.filepath, 'r') as db_file:
                try:
                    data = db_file.read()
                    db = json.loads(data)
                except Exception as e:
                    print(e)
                    db = { }
        except IOError:
            db = { }

        entry = {
            "Password" : encoded_password.decode('utf-8'),
            "New" : True,
            "Ease" : 2.0,
            "Due" : date.today().strftime("%Y/%m/%d"),
            "Interval" : 1,
            "Days Reviewed" : 0, 
        }
            
        if not site in db.keys():
            db[site] = { }
        try:
            db[site][username] = entry
        except KeyError:
            db[site] = { username : entry}
        
        with open(self.filepath, 'w') as db_file:
            json.dump(db, db_file)
    
    def edit_account(self, site, old_user, new_user):

        try:
            with open(self.filepath, 'r') as db_file:
                try:
                    data = db_file.read()
                    db = json.loads(data)
                except Exception as e:
                    print(e)
                    return
        except Exception as e:
            print(e)
            return
        
        try:
            db[site][new_user] = db[site].pop(old_user)
        except Exception as e:
            print(e)
        else:
            with open(self.filepath, 'w') as db_file:
                json.dump(db, db_file)
        
    def remove_account(self, site, username):
        try:
            with open(self.filepath, 'r') as db_file:
                data = db_file.read()
                db = json.loads(data)
                db[site].pop(username, None)
        except Exception as e:
            print(e)
        else:
            with open(self.filepath, 'w') as db_file:
                json.dump(db, db_file)
    
    def update_dues(self, to_update):
        try:
            with open(self.filepath, 'r') as db_file:
                try:
                    data = db_file.read()
                    db = json.loads(data)
                except Exception as e:
                    print(e)
                    return
        except Exception as e:
            print(e)
            return
        
        for site, username, entry in to_update:
            db[site][username] = {**entry, "Password" : self.encrypt(entry["Password"]).decode('utf-8')}
        
        try:
            json.dumps(db)
        except Exception as e:
            print(e)
        else:
            with open(self.filepath, 'w') as db_file:
                json.dump(db, db_file)
    
    def get_accounts(self, due):

        with open(self.filepath) as db_file:
            try:
                db = json.load(db_file)
            except Exception as e:
                print(e)
                db = { }

        # Get the new cards
        new_left = 20
        for site, account_list in db.items():
            for username, entry in account_list.items():
                if new_left == 0:
                    break
                if entry.get("New", False):
                    decoded_password = self.decrypt(entry["Password"].encode('utf-8'))
                    new_left -= 1
                    entry["New"] = False
                    entry["Buried"] = True
                    yield (site, username, {**entry, "Password" : decoded_password, "Attempts" : 3})

        # Get due cards
        for site, account_list in db.items():
            for username, entry in account_list.items():
                if entry.get("Buried", False):
                    continue
                accnt_due_date_raw = entry.get("Due", due.strftime("%Y/%m/%d"))
                accnt_due = datetime.date(datetime.strptime(accnt_due_date_raw, "%Y/%m/%d"))

                if due >= accnt_due:
                    decoded_password = self.decrypt(entry["Password"].encode('utf-8'))
                    yield (site, username, {**entry, "Password" : decoded_password, "Attempts" : 2})

class DayeaUI(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle('Project  Dayea')
        self.setGeometry(100, 100, 500, 80)

        self.generalLayout = QVBoxLayout()
        self._centralWidget = QWidget(self)
        self.setCentralWidget(self._centralWidget)
        self._centralWidget.setLayout(self.generalLayout)

        self._createMainLayout()
    
    def _createMainLayout(self):
        """Creates the main layout"""
        
        # Create the Master Key Part
        self.masterPasswordContainer = QHBoxLayout()
        self.topWidget = QWidget()
        self.enterMasterLabel = QLabel("Enter Master Password: ")
        self.masterPasswordLineEdit = QLineEdit()
        self.masterPasswordLineEdit.setMinimumWidth(300)
        self.updateMasterPasswordBtn = QPushButton("Submit")

        self.masterPasswordContainer.addWidget(self.enterMasterLabel)
        self.masterPasswordContainer.addWidget(self.masterPasswordLineEdit)
        self.masterPasswordContainer.addWidget(self.updateMasterPasswordBtn)
        self.topWidget.setLayout(self.masterPasswordContainer)
        self.generalLayout.addWidget(self.topWidget)

        # Create the Main Functionality Part
        # Add the buttons
        self.mainContainer = QVBoxLayout()
        self.startReviewBtn = QPushButton("Review")
        self.editEntriesBtn = QPushButton("Edit Entries")
        self.mainContainer.addWidget(self.startReviewBtn)
        self.mainContainer.addWidget(self.editEntriesBtn)
        
        # Add the Review Section Labels
        self.entryLabelContainer = QHBoxLayout()
        self.siteLabel = QLabel("Site: ")
        self.accountLabel = QLabel("Account: ")
        self.entryLabelContainer.addWidget(self.siteLabel)
        self.entryLabelContainer.addWidget(self.accountLabel)
        self.mainContainer.addLayout(self.entryLabelContainer)

        # Add the review section core functionality
        self.passwordInputContainer = QHBoxLayout()
        self.passwordInputLabel = QLabel("Enter Password: ")
        self.passwordEdit = QLineEdit()
        self.passwordEdit.setMinimumWidth(400)
        self.reviewSubmitBtn = QPushButton("Submit")
        self.passwordInputContainer.addWidget(self.passwordInputLabel)
        self.passwordInputContainer.addWidget(self.passwordEdit)
        self.passwordInputContainer.addWidget(self.reviewSubmitBtn)
        self.mainContainer.addLayout(self.passwordInputContainer)

        self.generalLayout.addLayout(self.mainContainer)

    def run(self):
        self.show()

            
if __name__ == '__main__':
    load_dotenv()

    # Create an instance of QApplication
    qtDayea = QApplication(sys.argv)
    # Show the GUI
    app = DayeaUI()
    app.run()
    # Execute the main loop
    sys.exit(qtDayea.exec_())

    master = input("Enter master password: ")
    dayea = Dayea(password=master, filepath='test.json')

    while input("Continue? (Y/N): ").upper() == 'Y':

        instructions = """What do you want to do?
            (1) Add Account
            (2) Remove Account
            (3) Edit Account Password
            (4) Edit Account Username
            (5) Memorize
        """

        CONST_INPUT_SITE_INSTRUCTION = "Enter site name: "
        CONST_INPUT_USER_INSTRUCTION = "Enter username/email: "
        CONST_INPUT_PASS_INSTRUCTION = "Enter your password (be careful of people snooping): "        

        mode = int(input(instructions))

        if mode == 1 or mode == 3:
            site = input(CONST_INPUT_SITE_INSTRUCTION)
            username = input(CONST_INPUT_USER_INSTRUCTION)
            password = input(CONST_INPUT_PASS_INSTRUCTION)
            dayea.add_account(site, username, password)

        elif mode == 2:
            site = input(CONST_INPUT_SITE_INSTRUCTION)
            username = input(CONST_INPUT_USER_INSTRUCTION)
            dayea.remove_account(site, username)
        
        elif mode == 4:
            site = input(CONST_INPUT_SITE_INSTRUCTION)
            old_user = input("Enter old username/email: ")
            new_user = input("Enter new username/email: ")
            dayea.edit_account(site, old_user, new_user)
        
        elif mode == 5:

            cur_date = date.today()
            review_stack = deque(dayea.get_accounts(cur_date))
            to_update = []

            while review_stack:

                site, username, entry = review_stack.popleft()

                print("Enter password for: ", site, username)

                password = entry["Password"]
                passed = False

                for i in range(3):
                    attempt = input()
                    if attempt == password:
                        print("Correct!")
                        passed = True
                        attempts_taken = i+1
                        break
                    else:
                        print(f"Wrong. {3-i-1} attempts left...")

                if passed:
                    attempts_left = entry.get("Attempts", 2) - 1
                    if attempts_left:
                        review_stack.append((site, username, {**entry, "Attempts" : attempts_left}))
                    else:
                        entry.pop('Buried', None)
                        entry.pop("Attempts", None)
                        entry.pop("New", None)

                        if entry.get("Days Reviewed", 0) == 0:
                            new_interval = 2
                        elif entry.get("Days Reviewed", 0) == 1:
                            new_interval = 6
                        else:
                            new_interval = int(0.5 + entry.get("Interval", 2) * entry["Ease"])

                        entry["Due"] = (cur_date + dt.timedelta(days=new_interval)).strftime("%Y/%m/%d")
                        entry["Ease"] += 0.075 * (3 - attempts_taken)
                        entry["Interval"] = new_interval
                        entry["Days Reviewed"] = entry.get("Days Reviewed", 0) + 1
                        to_update.append((site, username, entry))
                else:
                    print("Password:", password)
                    ease = max(entry["Ease"] - 0.2, 1.30)
                    review_stack.append((site, username, {**entry, "Ease" : ease}))
            
            dayea.update_dues(to_update)
            