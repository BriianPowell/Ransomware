# [TEST]
# Test RSA Files

import RSAMain, sys, os

publ_path = "public.pem" 
priv_path = "private.pem"

frozen = 'not'
if getattr(sys, 'frozen', False):
        frozen = 'ever so'
        applicationPath = sys._MEIPASS
else:
        applicationPath = os.path.dirname(os.path.abspath(__file__))

os.chdir(applicationPath)
enc = RSAMain.RSAEncryption()
privk,pubk = enc.findRSAKey(os.getcwd())
enc.encryptDir()


# publ_path = "RSAFileEncrypt\public.pem" 
# priv_path = "RSAFileEncrypt\private.pem"
# fp = "RSAFileEncrypt\image.jpg"
# cfp = "RSAFileEncrypt\image.encrypt"

# enc = RSAMain.RSAEncryption()
# privk,pubk = enc.findRSAKey("RSAFileEncrypt")
# print("Public key:", str(pubk))
# print("Private Key:", str(privk))

# rsc, ct, i_v, htag, ext = enc.encryptRSA(fp, publ_path)
# enc.decryptRSA(cfp, priv_path, rsc, ct, i_v, htag, ext)