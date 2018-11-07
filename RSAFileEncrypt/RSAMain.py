import os
import var
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/hazmat/primitives/padding/
# https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/

# Brian Powell @BriianPowell
# CECS 378 - Cyber Security
# Aliasgari