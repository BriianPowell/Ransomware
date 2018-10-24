import os
import var
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/

# Brian Powell @BriianPowell
# CECS 456 - Machine Learning
# Aliasgari

class HMACEncryption:
    def __init__(self, ENCKEY, HMACKEY):
        self.ENCKEY = ENCKEY
        self.HMACKEY = HMACKEY

    # (C, IV, tag)= MyencryptMAC(message, EncKey, HMACKey)
    # In this method, you will generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).  
    # You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).
    def encryptHMAC(self, message, ENCKEY, HMACKEY):
        if(len(ENCKEY) < var.KEYSIZE):
            print("Key is less than 32 bytes.")
            return -1

        # Checks to see if cipher and mode are supported
        backend = default_backend()

        # Used to generator 16 byte Initialization Vector
        iv = os.urandom(var.IVSIZE)

        # Creates a Cipher that combines the AES algorithm and CBC mode
        # 256 bit key = 14 rounds of AES
        cipher = Cipher(algorithms.AES(ENCKEY), modes.CBC(iv), backend=backend)

        # Padder required to pad the CipherText
        # Makes sure Data is correct size for encryption
        padder = padding.PKCS7(var.PADDINGSIZE).padder()
        pd = padder.update(message) + padder.finalize()

        # Creates encryptor object to send padded data to
        # padded data is to make sure we have a fixed size of 128
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(pd) + encryptor.finalize()

        # Create HMAC tag based off the SHA256 algorithm and key 
        # Update cipher_text with hash
        h_tag = hmac.HMAC(HMACKEY, hashes.SHA256(), backend=backend)
        h_tag.update(cipher_text)

        return cipher_text, iv, h_tag.finalize()

    # (P) = AESDecrypt(cipher, key, hkey, tag, iv):
    # runs the symmetric opposite of AESEncrypt and returns plain_text
    def decryptHMAC(self, CT, ENCKEY, HMACKEY, IV, TAG):
        # Checks to see if cipher and mode are supported
        backend = default_backend()
        
        # Create HMAC tag based off the SHA256 algorithm and key 
        # Update cipher_text with hash
        h_tag = hmac.HMAC(HMACKEY, hashes.SHA256(), backend=backend)
        h_tag.update(CT)

        #Check if correct signature
        try:
            h_tag.verify(TAG)
        except:
            print("Signature does not match digest.")

        # Creates a Cipher that combines the AES algorithm and CBC mode
        # 256 bit key = 14 rounds of AES
        cipher = Cipher(algorithms.AES(ENCKEY), modes.CBC(IV), backend=backend)

        # Creates decryptor object to send cipher data to
        # Cipher data is encrypted padded data
        decryptor = cipher.decryptor()
        pt = decryptor.update(CT) + decryptor.finalize()
  
        # Data has been unencrypted
        # Need to unpad to make sure data is plain again
        unpadder = padding.PKCS7(var.PADDINGSIZE).unpadder()
        plain_text = unpadder.update(pt) + unpadder.finalize()
    
        return plain_text

    # (C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC (filepath)
    # In this method, you'll generate a 32Byte key.
    # You open and read the file as a string. 
    # You then call the above method to encrypt your file using the key you generated. 
    # You return the cipher C, IV, key and the extension of the file (as a string).
    def fileEncryptHMAC(self, filepath):
        # Generate Key of Size 32
        # enckey = os.urandom(var.KEYSIZE)
        # hmackey = os.urandom(var.HMACSIZE)
        # IMPORTANT: Use the classes initialized keys for encryption/decryption and HMAC


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
        cipher_text, iv, htag = self.encryptHMAC(bytedata, self.ENCKEY, self.HMACKEY)

        # write encrypted file data to the newly created file path
        # write is done in write-binary mode
        encryptFile = open(out, "wb")
        encryptFile.write(cipher_text)
        encryptFile.close()
    
        return cipher_text, self.ENCKEY, self.HMACKEY, iv, htag, ext

    def fileDecryptHMAC(self, cfilepath, ENCKEY, HMACKEY, IV, TAG, EXT):
        # Open file in read-binary mode
        # Read binary data to bytedata
        file = open(cfilepath, "rb")
        bytedata = file.read()
        file.close()

        # Get plain_text back from Decryption function
        plain_text = self.decryptHMAC(bytedata, ENCKEY, HMACKEY, IV, TAG)
        
        filepath = cfilepath.split(var.ENCEXT)[0] + "new" + EXT
        # Touch a file called decypted.txt in write-binary mode
        # Write plain_text to the new file
        decrypt = open(filepath, "wb")
        decrypt.write(plain_text)
        decrypt.close()

# [TEST]
# Generating a key
key = os.urandom(var.KEYSIZE)
hmackey = os.urandom(var.HMACSIZE)

# Test Message
enc = HMACEncryption(key, hmackey)
# message = b"hello brochachos"
# ct, iv, ht = enc.encryptHMAC(message, enc.ENCKEY, enc.HMACKEY)

# Test File Encryption
ct, ek, hk, iv, ht, ext = enc.fileEncryptHMAC("HMACFileEncrypt\\image.jpg")
enc.fileDecryptHMAC("HMACFileEncrypt\\image.encrypt", ek, hk, iv, ht, ext)

# # Print Results
# print("Original Message: ", message)
# print("Cipher text: ", ct)
# print("Decrypted Message: ", enc.decryptHMAC(ct, enc.ENCKEY, iv, enc.HMACKEY, ht))