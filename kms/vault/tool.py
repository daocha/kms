# Date: 31 Aug 2018
# Author: Ray LI <ray@daocha.me>
""" Tool for encryption """

from kms.common import rsa
import os

this_dir = os.path.dirname(os.path.abspath(__file__))
encrypted_json = "%s/../vault/encrypted.json" % this_dir

def readJson():
    if "pri_key" not in globals():
        global pri_key
        pri_key = rsa.importDefaultPrivateKey(False)
    config = rsa.readEncryptedFile(encrypted_json, pri_key)
    print(config.decode("utf-8"))

def encryptJson():
    # encrypt
    if "pri_key" not in globals():
        global pri_key
        pri_key = rsa.importDefaultPrivateKey(False)
    rsa.encryptFile(encrypted_json, pri_key)

def decryptJson():
    # decrypt
    if "pri_key" not in globals():
        global pri_key
        pri_key = rsa.importDefaultPrivateKey(False)
    rsa.decryptFile(encrypted_json, pri_key)
