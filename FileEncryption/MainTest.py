import Main

# File Paths
testFile = 'FileEncryption\\test_file.txt'
cTestFile = 'FileEncryption\\test_file.encrypt'

# [TEST]
# Testing File Encryption
enc = Main.Encryption()
ct, iv, key, ext = enc.AESFileEncrypt(testFile)
enc.AESFileDecrypt(cTestFile, key, iv, ext)

# Test Message
message = b"hello brochachos"
ct, iv = enc.AESEncrypt(message, key)

# Print Results
print("Original Message: ", message)
print("Cipher text: ", ct)
print("Decrypted Message: ", enc.AESDecrypt(ct, key, iv))