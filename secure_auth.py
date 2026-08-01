import bcrypt
import json
import os
import re
import time

DB_FILE = "users.json"
MIN_LEN = 12
MAX_ATTEMPTS = 5
LOCK_TIME = 60


def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}


def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def check_password_strength(pw):
    if len(pw) < MIN_LEN:
        return False, "needs at least 12 characters"
    if not re.search(r"[A-Z]", pw):
        return False, "needs an uppercase letter"
    if not re.search(r"[a-z]", pw):
        return False, "needs a lowercase letter"
    if not re.search(r"[0-9]", pw):
        return False, "needs a number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", pw):
        return False, "needs a special character"
    return True, ""


class UserManager:
    def __init__(self):
        self.users = load_db()
        self.failed_logins = {}

    def register(self, username, password):
        if username in self.users:
            return False, "username taken"

        ok, reason = check_password_strength(password)
        if not ok:
            return False, reason

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        self.users[username] = hashed.decode()
        save_db(self.users)
        return True, "registered"

    def locked_out(self, username):
        entry = self.failed_logins.get(username)
        if not entry:
            return False
        if entry["count"] >= MAX_ATTEMPTS and time.time() < entry["until"]:
            return True
        return False

    def login(self, username, password):
        if self.locked_out(username):
            return False, "too many attempts, try again later"

        if username not in self.users:
            self._fail(username)
            return False, "wrong username or password"

        stored = self.users[username].encode()
        if bcrypt.checkpw(password.encode(), stored):
            self.failed_logins.pop(username, None)
            return True, "logged in"

        self._fail(username)
        return False, "wrong username or password"

    def _fail(self, username):
        entry = self.failed_logins.setdefault(username, {"count": 0, "until": 0})
        entry["count"] += 1
        if entry["count"] >= MAX_ATTEMPTS:
            entry["until"] = time.time() + LOCK_TIME


if __name__ == "__main__":
    mgr = UserManager()

    print(mgr.register("alice", "SecurePass123!"))
    print(mgr.register("alice", "AnotherPass123!"))
    print(mgr.register("bob", "weak"))

    print(mgr.login("alice", "SecurePass123!"))
    print(mgr.login("alice", "WrongPass1!"))

    for i in range(6):
        print(i + 1, mgr.login("alice", "WrongPass1!"))

    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)