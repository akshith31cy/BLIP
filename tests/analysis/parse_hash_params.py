# tests/analysis/parse_hash_params.py
import re, csv, os
BCRYPT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports/bcrypt_hashes.txt"
ARGON = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports/argon2_hashes.txt"
OUT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/hash_params.csv"

rows = []
# bcrypt parsing
if os.path.exists(BCRYPT):
    with open(BCRYPT, 'r', errors='ignore') as f:
        for i,line in enumerate(f,1):
            line=line.strip()
            # typical bcrypt: $2b$12$22charsalt22charsaltrest...
            m = re.match(r'^\$(2[aby])\$(\d{1,2})\$(.{22})(.+)$', line)
            if m:
                algo, cost, salt, rest = m.groups()
                rows.append(['bcrypt', i, algo, int(cost), len(salt), line])
            else:
                rows.append(['bcrypt', i, 'unknown', None, None, line])

# argon2 parsing (typical: $argon2i$v=19$m=65536,t=3,p=1$base64salt$base64hash)
if os.path.exists(ARGON):
    with open(ARGON, 'r', errors='ignore') as f:
        for i,line in enumerate(f,1):
            line=line.strip()
            if line.startswith('$argon2'):
                rows.append(['argon2', i, line.split('$')[1], None, None, line])
            else:
                rows.append(['argon2', i, 'unknown', None, None, line])

with open(OUT,'w',newline='',encoding='utf-8') as out:
    w = csv.writer(out)
    w.writerow(['algorithm','index','subtype_or_id','cost','salt_len','raw'])
    w.writerows(rows)
print("Wrote", OUT)
