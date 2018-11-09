import HMACMain

# File Paths
testFile = "HMACFileEncrypt\image.jpg"
cTestFile = "HMACFileEncrypt\image.encrypt"

# [TEST]
# Test Message Encryption
enc = HMACMain.HMACEncryption()
message = b"hello brochachos"
ct, iv, ht = enc.encryptHMAC(message, enc.ENCKEY, enc.HMACKEY)

print("Original Message: ", message)
print("Enc_Key: ", enc.ENCKEY)
print("Hmc_Key: ", enc.HMACKEY)
print("Cipher text: ", ct)
print("Tag: ", ht)
print("Decrypted Message: ", enc.decryptHMAC(ct, enc.ENCKEY, enc.HMACKEY, iv, ht))

# Test File Encryption
ct, ek, hk, i_v, htag, ext = enc.fileEncryptHMAC(testFile)
enc.fileDecryptHMAC(cTestFile, ek, hk, i_v, htag, ext)