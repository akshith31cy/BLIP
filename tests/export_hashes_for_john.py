# tests/export_hashes_for_john.py
import sqlite3, os, json

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB = os.path.join(ROOT, "users.db")
OUT = os.path.join(ROOT, "tests", "john_exports")
os.makedirs(OUT, exist_ok=True)

def export_bcrypt():
    out_file = os.path.join(OUT, "bcrypt_hashes.txt")
    with open(out_file, "w", encoding="utf-8") as f_out:
        conn = sqlite3.connect(DB); cur = conn.cursor()
        cur.execute("SELECT username, password_hash FROM users")
        for username, ph in cur:
            if ph and ph.startswith("$2"):
                f_out.write(f"{username}:{ph}\n")
        conn.close()
    print("bcrypt export ->", out_file)

def export_argon2():
    out_file = os.path.join(OUT, "argon2_hashes.txt")
    with open(out_file, "w", encoding="utf-8") as f_out:
        conn = sqlite3.connect(DB); cur = conn.cursor()
        cur.execute("SELECT username, password_hash FROM users")
        for username, ph in cur:
            if ph and ph.startswith("$argon2"):
                f_out.write(f"{ph}\n")
        conn.close()
    print("argon2 export ->", out_file)

if __name__ == "__main__":
    export_bcrypt()
    export_argon2()
