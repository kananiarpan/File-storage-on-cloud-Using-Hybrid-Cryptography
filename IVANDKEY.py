from cryptography.fernet import Fernet
import os
def generateIV():
    iv1 = os.urandom(16)
    iv2 = os.urandom(8)
    return iv1,iv2


def generatekey():
    key1 = os.urandom(16)
    key2 = Fernet.generate_key()
    return key1,key2

