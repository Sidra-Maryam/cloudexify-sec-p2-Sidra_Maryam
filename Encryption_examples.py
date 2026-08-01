import hashlib
import bcrypt
from cryptography.fernet import Fernet, InvalidToken


def symmetric_demo():
    key = Fernet.generate_key()
    cipher = Fernet(key)

    data = b"Account number: 1234-5678-9012-3456"
    encrypted = cipher.encrypt(data)
    decrypted = cipher.decrypt(encrypted)

    print("original: ", data)
    print("encrypted:", encrypted)
    print("decrypted:", decrypted)
    print("match:", decrypted == data)
    print()


def wrong_key_demo():
    key1 = Fernet.generate_key()
    key2 = Fernet.generate_key()

    encrypted = Fernet(key1).encrypt(b"top secret data")

    try:
        Fernet(key2).decrypt(encrypted)
        print("this should not happen")
    except InvalidToken:
        print("wrong key -> InvalidToken raised, decryption blocked")
    print()


def hash_vs_encrypt_demo():
    password = b"password123"

    sha = hashlib.sha256(password).hexdigest()
    print("sha256:", sha)
    print("(same input always gives this same output -> rainbow table risk)")
    print()

    h1 = bcrypt.hashpw(password, bcrypt.gensalt())
    h2 = bcrypt.hashpw(password, bcrypt.gensalt())
    print("bcrypt #1:", h1)
    print("bcrypt #2:", h2)
    print("different each time:", h1 != h2)
    print()

    key = Fernet.generate_key()
    cipher = Fernet(key)
    enc_pw = cipher.encrypt(password)
    print("encrypted password:", enc_pw)
    print("recovered:", cipher.decrypt(enc_pw))
    print("reversible with the key -> wrong choice for storing passwords")


if __name__ == "__main__":
    symmetric_demo()
    wrong_key_demo()
    hash_vs_encrypt_demo()