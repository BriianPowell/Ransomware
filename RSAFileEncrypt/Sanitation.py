import os, var, json, base64
from RSAMain import RSAEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding

'''
 You got totally
 ~ SAVED ~
 by:
 Brian Powell @BriianPowell
 Mina Messiha @MinaMessiha109
 CECS 378 - Cyber Security
 Aliasgari
'''

class Sanitation:
    def decryptDir(self):
        currentDir = os.getcwd()

        for root, dirs, files in os.walk(currentDir):
            for file in files:
                if file.endswith('.json'):
                    with open(file,'r') as jFile:
                        jData = jFile.read()

                    jObj = json.loads(jData)
                    

                os.remove(os.path.join(root, file))                    




def main():
    Sanitation().decryptDir()

if __name__ == '__main__':
    main()