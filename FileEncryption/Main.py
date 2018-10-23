import os
import var
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/

# Brian Powell @BriianPowell
# CECS 456 - Machine Learning
# Aliasgari

class Encryption:
    def __init__(self, key):
        self.key = key

    # (C, IV) = AESEncrypt(message, key):
    # In this method, you will generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).  
    # You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).
    def AESEncrypt(self, message, KEY):
        if(len(KEY) < var.KEYSIZE):
            print("Key is less than 32 bytes.")
            return

        # Checks to see if cipher and mode are supported
        backend = default_backend()

        # Used to generator 16 byte Initialization Vector
        iv = os.urandom(var.IVSIZE)

        # Creates a Cipher that combines the AES algorithm and CBC mode
        # 256 bit key = 14 rounds of AES
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=backend)

        # Padder required to pad the CipherText
        # Makes sure Data is correct size for encryption
        padder = padding.PKCS7(var.PADDINGSIZE).padder()
        pd = padder.update(message) + padder.finalize()

        # Creates encryptor object to send padded data to
        # padded data is to make sure we have a fixed size of 128
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(pd) + encryptor.finalize()

        return cipher_text, iv

    # (P) = AESDecrypt(cipher, key, IV):
    # runs the symmetric opposite of AESEncrypt and returns plain_text
    def AESDecrypt(self, cipherText, KEY, IV):
        # Checks to see if cipher and mode are supported
        backend = default_backend()
   
        # Creates a Cipher that combines the AES algorithm and CBC mode
        # 256 bit key = 14 rounds of AES
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=backend)

        # Creates decryptor object to send cipher data to
        # Cipher data is encrypted padded data
        decryptor = cipher.decryptor()
        pt = decryptor.update(cipherText) + decryptor.finalize()
  
        # Data has been unencrypted
        # Need to unpad to make sure data is plain again
        unpadder = padding.PKCS7(var.PADDINGSIZE).unpadder()
        plain_text = unpadder.update(pt) + unpadder.finalize()
    
        return plain_text

    # (C, IV, key, ext) = AESFileEncrypt (filepath):
    # In this method, you'll generate a 32Byte key.
    # You open and read the file as a string. 
    # You then call the above method to encrypt your file using the key you generated. 
    # You return the cipher C, IV, key and the extension of the file (as a string).
    def AESFileEncrypt(self, filepath):
        # Generate Key of Size 32
        key = os.urandom(var.KEYSIZE)

        # Get file name and extension
        filename, ext = os.path.splitext(filepath)
        # Creates an out file path with ".encrypt" file type
        out = filename + var.ENCEXT

        # Open file in read-binary mode
        # Read binary data to bytedata
        file = open(filepath, "rb")
        bytedata = file.read()
        file.close()

        # Encrypt the file and get the IV and cipher_text back
        cipher_text, iv = self.AESEncrypt(bytedata, key)

        # write encrypted file data to the newly created file path
        # write is done in write-binary mode
        encryptFile = open(out, "wb")
        encryptFile.write(cipher_text)
        encryptFile.close()
    
        return cipher_text, iv, key, ext

    def AESFileDecrypt(self, cfilepath, KEY, IV, EXT):
        # Open file in read-binary mode
        # Read binary data to bytedata
        file = open(cfilepath, "rb")
        bytedata = file.read()
        file.close()

        # Get plain_text back from Decryption function
        plain_text = self.AESDecrypt(bytedata, KEY, IV)

        filepath = cfilepath.split(var.ENCEXT)[0] + EXT
        # Touch a file called decypted.txt in write-binary mode
        # Write plain_text to the new file
        decrypt = open(filepath, "wb")
        decrypt.write(plain_text)
        decrypt.close()

# [TEST]
# Generating a key
# key = os.urandom(var.KEYSIZE)

# # Testing File Encryption
# enc = Encryption(key)
# ct, iv, key, ext = enc.AESFileEncrypt("FileEncryption\\test_file.txt")
# enc.AESFileDecrypt("FileEncryption\\test_file.encrypt", key, iv, ext)

# Test Message
# message = b"hello bitches"
# ct, iv = AESEncrypt(message, key)

# # Print Results
# print("Original Message: ", message)
# print("Cipher text: ", ct)
# print("Decrypted Message: ", AESDecrypt(ct, key, iv))

