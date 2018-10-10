import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# https://cryptography.io/en/latest/hazmat/primitives/aead/

# (C, IV) = Myencrypt(message, key):
#
# In this method, you will generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).  
# You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).
def myEncrypt(message, key):
    key = ChaCha20Poly1305.generate_key();
    chacha = ChaCha20Poly1305(key);
    nonce = os.urandom(12);
    ct = chacha.encrypt(nonce, message, IV);



# (C, IV, key, ext) = MyfileEncrypt (filepath):
# In this method, you'll generate a 32Byte key.
# You open and read the file as a string. 
# You then call the above method to encrypt your file using the key you generated. 
# You return the cipher C, IV, key and the extension of the file (as a string).
def myFileEncrypt(filepath):