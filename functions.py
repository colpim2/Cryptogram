# Importar modulo Cryto usando el comando
# pip3 install pycryptodome

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import hmac
import hashlib

import rsa


# Bob encrypts - server
# 0. Read user's password
# 1. Generating public and private keys(Asymmetric - RSA), random key(Symmetric - PBKDF)
# 2. Store keys
# 3. Encrypt symmetric key using Alice's public key
# 4. Encrypt message using the random key using AES
# 5. Apply digital signature to message using Bob's private key

# Alice decrypts - client
# 0. Read user's password
# 1. Generate public(RSA) and private keys(PBKDF)
# 2. Store keys: puclic keys as plain text and private keys using hash funtion
# 6. Verify message integrity upon receipt.
# 7. Dencrypt random key using Alice's private key
# 8. Verify digital signature with Bob's public key
# 9. Dencrypt message using the decrypt random key of prior step using AES


# ---------------------- BOTH ------------------------
# 0. Read user's password
# 1. Generating public and private keys(Asymmetric - RSA), random key(Symmetric - PBKDF)
# 2. Store keys
# 4. Encrypt message using the symmetric key using AES


def symmetricKeys_PBKDF(password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
    return key

def generatingAsymmetricKeys():

    key = RSA.generate(2048)

    # Obtener la clave pública y privada
    public_key = key.publickey().export_key()
    private_key = key.export_key()

    return public_key, private_key






# 2. Store keys
# FRANCISCO


# 3. Encrypt random key using Alice's public key

def encryptMessage(publicKey, message):
    cipher = PKCS1_OAEP.new(publicKey)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def decryptMessage(privateKey, ciphertext):
    key = RSA.import_key(privateKey)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext



# message - symmetric random key 
def encryption(publickey, data):
    ciphertext = rsa.encrypt(data, publickey)
    return ciphertext



# 4. Encrypt message using the random key using AES



# 5. Apply digital signature to message using Bob's private key
def digitalSignature_Hash(privatekey,publickey):
    data = 'Hello World Again!'.encode('utf8')  # message in cipher text
    hash = hashlib.sha3_256(data).hexdigest()
    #hash = rsa.compute_hash(data, 'SHA-3')  # Hashing plain text to verify authentication message
    signature = rsa.sign(hash, privatekey, 'SHA-3')  #Bob's signature




# ---------------------- ALICE -----------------------
# 6. Verify message integrity upon receipt.
# @ Params: original_hash, msj_received strings with UTF-8 encoding 
def VerifyHash(original_hash,msj_received):
  # Generate hash for the msj received
  expected_hash = hashlib.sha3_256(msj_received).hexdigest()

  # Compare the hashes
  if original_hash == expected_hash:
      print("Hash verification successful!")
      return 0
  else:
      print("Hash verification failed.")
      return 1

# 7. Dencrypt random key using Alice's private key
def dencryption(privatekey, cipher_random_key):
    message2 = rsa.decrypt(cipher_random_key, privatekey)
    print(message2)
    print(message2.decode('utf8'))


# 8. Verify digital signature with Bob's public key
def verify_digitalSignature_Hash(privatekey,publickey, data, signature):
    rsa.verify(data, signature, publickey)
    data2 = 'Hello World2'.encode('utf8')




# 9. Dencrypt message using the decrypt random key using AES


def main():
    publickey, privatekey = generatingKeys()
    encryption(publickey, privatekey)
    digitalSignature_Hash(publickey, privatekey)






