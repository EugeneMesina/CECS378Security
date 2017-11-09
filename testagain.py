import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


backend = default_backend()

def pad(blockSize, s):
    return s + (blockSize - len(s) % blockSize) * chr(blockSize - len(s) % blockSize)
def unpad(s):
    return s[:-ord(s[-1])]

def myEncrypt(message, key):
    iv = os.urandom(16)
    blockSize = 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    paddedMessage = pad(blockSize, message)
    ct = encryptor.update(paddedMessage) + encryptor.finalize()
    return (ct,iv)
def myDecrypt(key,ct,iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpad(ct)
    return(decryptor.update(ct) + decryptor.finalize())
def myFileEncrypt(filepath):
    ext = "txt"
    filee = os.path.join(filepath, "read" + "." + ext)
    key = os.urandom(32)
    test = open(filee, 'r')
    Message = test.readline()
    ct, iv = myEncrypt(Message, key)
    filee2 = os.path.join(filepath, "encrypt" + "." + ext)
    test = open(filee2, 'w')
    test.write(ct)

    return (ct, iv, key, ext)
def myFileDecrypt(filepath,ct,iv,key,ext):
    filee = os.path.join(filepath, "write" + "." + ext)
    test = open(filee, 'w')
    test.write(myDecrypt(key,ct,iv))
    return (myDecrypt(key,ct,iv))

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    #encrypt file to get the key
    ct, iv, key, ext = myFileEncrypt(filepath)
    #filee = os.path.join(RSA_Publickey_filepath, "FunTime.pem")
    #load the public key
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_exponent_key = serialization.load_pem_public_key(
                key_file.read(),
            #    password = None,
                backend=default_backend()
                )
    public_key = public_key.public_key()
    RSACipher = public_key.encrypt(
            key,
            padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
            )
    return RSACipher, ct, iv, ext

def MyRSADecrypt(RSACipher,RSA_Privatekey_filepath,ct,iv, ext):
    #filee = os.path.join(RSA_Publickey_filepath, "FunTime.pem")
    #load the public key
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None,
                backend=default_backend()
                )
        private_key = private_key.private_key()
        key = private_key.decrypt(
                RSACipher,
                padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                        )
                )




    return


filepath = "/Users/jinchronic/Desktop/"
RSACipher, ct, iv, ext = MyRSAEncrypt(filepath,filepath);
ct, iv, key, ext = myFileEncrypt(filepath)
#ct, iv = myEncrypt(raw_input("Message: "), key)
print(MyRSADecrypt(filepath,filepath,ct,iv,ext))
print(myFileDecrypt(filepath,ct,iv,key,ext))
print(myDecrypt(key,ct,iv))
