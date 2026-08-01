# Cryptography & Password Security

Password authentication system and encryption examples built in Python for CloudExify Cybersecurity, Month 1, Project 2.

## Files

- `secure_auth.py`: registration/login system using bcrypt, password strength checks, and login rate limiting.
- `encryption_examples.py`: Fernet symmetric encryption, a wrong-key failure case, and a hashing vs encryption comparison.

## Setup

```bash
pip install bcrypt cryptography
python secure_auth.py
python Encryption_examples.py
```

## Notes

- Passwords are hashed with bcrypt, never encrypted, hashing is one-way so a leaked database can't be turned back into plaintext passwords.
- `bcrypt.gensalt()` generates a random salt per user, so identical passwords never produce identical stored hashes. This is what defeats rainbow table attacks, unlike plain SHA-256.
- Login has a lockout after 5 failed attempts within 60 seconds, to slow down brute-force attempts.
- Failed login messages don't say whether the username or password was wrong, so they can't be used to enumerate valid accounts.
- Sensitive data like account numbers uses Fernet (reversible) encryption instead of hashing, since it needs to be readable again later, the opposite requirement from password storage.
