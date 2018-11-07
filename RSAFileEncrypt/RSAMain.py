import os
import var
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/
# https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

# Brian Powell @BriianPowell
# CECS 378 - Cyber Security
# Aliasgari

class RSAEncryption:
    def __init__(self):
        self.ENCKEY = os.urandom(var.KEYSIZE)
        self.HMACKEY = os.urandom(var.KEYSIZE)

    #Step 1:
    # Next, you will a script that looks for a pair of RSA Public and private key (using a CONSTANT file path; PEM format). 
    # If the files do not exist (use OS package) then generate the RSA public and private key (2048 bits length) 
    # using the same constant file path.
    

    # (RSACipher, C, IV, tag, ext)= MyencryptRSA(filepath, RSA_Publickey_filepath)
    # In this method, you first call MyfileEncryptMAC (filepath) which will return (C, IV, tag, Enckey, HMACKey, ext). 
    # You then will initialize an RSA public key encryption object and load pem publickey from the RSA_publickey_filepath. 
    # Lastly, you encrypt the key variable ("key"= EncKey+ HMACKey (concatenated)) using the RSA publickey in OAEP 
    # padding mode. The result will be RSACipher. 
    # You then return (RSACipher, C, IV, ext).
    def encryptRSA(self, filepath, RSA_Publickey_filepath):
        # (CT, ekey, hkey, iv, tag, ext) = MyfileEncryptMAC(filepath)
        ct, ek, hk, iv, htag, ext = self.fileEncryptHMAC(filepath)



        
        return RSACipher, ct, iv, htag, ext

    # (P) = decryptRSA(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath) 
    # which does the exactly inverse of the above and generate the decrypted file using your 
    # previous decryption methods.
    def decryptRSA(self, CT, ENCKEY, HMACKEY, IV, TAG):
        


        return 

    # (CT, ekey, hkey, iv, tag, ext) = MyfileEncryptMAC(filepath)
    def fileEncryptHMAC(self, filepath):
        # Generate Keys of Size 32
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

    # (File) = fileDecryptHMAC(cfilepath, ENCKEY, HMACKEY, IV, TAG, EXT)
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

    # (C, IV, tag)= encryptHMAC(message, EncKey, HMACKey)
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

        # Create HMAC tag object based off the SHA256 algorithm and key 
        # Update cipher_text with hashed HMAC tag    
        h_tag = hmac.HMAC(HMACKEY, hashes.SHA256(), backend=backend)
        h_tag.update(cipher_text)

        return cipher_text, iv, h_tag.finalize()

    # (P) = decryptHMAC(cipher, key, hkey, iv, htag):
    # runs the symmetric opposite of encryptHMAC and returns plain_text
    def decryptHMAC(self, CT, ENCKEY, HMACKEY, IV, TAG):
        # Checks to see if cipher and mode are supported
        backend = default_backend()
        
        # Create HMAC tag object based off the SHA256 algorithm and Hkey 
        # Update cipher_text with hash
        h_tag = hmac.HMAC(HMACKEY, hashes.SHA256(), backend=backend)
        h_tag.update(CT)

        # Check if correct signature
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