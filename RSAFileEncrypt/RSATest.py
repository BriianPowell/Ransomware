import RSAMain

# [TEST]
# Test RSA Files
publ_path = "RSAFileEncrypt\public.pem" 
priv_path = "RSAFileEncrypt\private.pem"
fp = "RSAFileEncrypt\image.jpg"
cfp = "RSAFileEncrypt\image.encrypt"

enc = RSAMain.RSAEncryption()
privk,pubk = enc.findRSAKey("RSAFileEncrypt")
print("Public key:", str(pubk))
print("Private Key:", str(privk))

rsc, ct, i_v, htag, ext = enc.encryptRSA(fp, publ_path)
enc.decryptRSA(cfp, priv_path, rsc, ct, i_v, htag, ext)