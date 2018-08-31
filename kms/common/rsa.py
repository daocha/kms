from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Cryptodome import Random
from base64 import b64encode, b64decode
import logging
import os

hash = "SHA-512"
if os.environ.get('KMS_KEYRING') is not None:
    prk_path = os.environ.get('KMS_KEYRING')
else:
    this_dir = os.path.dirname(os.path.abspath(__file__))
    prk_path = "%s/../vault/privatekey.pem" % this_dir

def newkeys(keysize):
    logger = logging.getLogger(__name__)
    logger.info("Generating key, size=%dc" % keysize)
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private

def importDefaultPrivateKey(generatePrivateKey=None):
    logger = logging.getLogger(__name__)
    if((os.path.exists(prk_path) is False or os.stat(prk_path).st_size == 0
       or os.path.isfile(prk_path) is False) and generatePrivateKey is True):
        pub_key, pri_key = newkeys(4096)
        logger.info("Exporting key: path: %s" % prk_path)
        pem = pri_key.exportKey(format="PEM")
        with open(prk_path, 'wb') as f:
            f.write(pem)
    logger.info("Importing key: path: %s" % prk_path)
    with open(prk_path, 'r') as f:
        #logger.info("Reading Key: %s" % r.read())
        return importKey(f.read())

def importKey(externKey):
    return RSA.import_key(externKey)

def encryptFile(file_path, pub_key):
    with open(file_path, 'r+b') as f:
        plain_content = f.read()[:-1]
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plain_content)
        f.truncate(0)
        f.seek(0)
        [ f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

def decryptFile(file_path, priv_key):
    with open(file_path, 'r+b') as f:
        enc_session_key, nonce, tag, ciphertext = \
        [ f.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1) ]
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_content = cipher_aes.decrypt_and_verify(ciphertext, tag)
        f.truncate(0)
        f.seek(0)
        f.write(decrypted_content)

def readEncryptedFile(file_path, priv_key):
    with open(file_path, 'r+b') as f:
        enc_session_key, nonce, tag, ciphertext = \
        [ f.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1) ]
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_content = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_content
