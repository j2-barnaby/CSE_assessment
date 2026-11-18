from cryptography.fernet import Fernet, InvalidToken
import sys

key = sys.argv[1].encode()
token = sys.argv[2].encode()

try:
    plaintext = Fernet(key).decrypt(token)
except InvalidToken:
    sys.exit("Could not decrypt: wrong key or damaged token")

print(plaintext.decode(errors="replace"))
