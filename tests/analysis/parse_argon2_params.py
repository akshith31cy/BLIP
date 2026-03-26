# tests/analysis/parse_argon2_params.py
import re, csv, os
ARGON = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports/argon2_hashes.txt"
OUT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/argon2_params.csv"
rows=[]
if os.path.exists(ARGON):
    with open(ARGON,'r',errors='ignore') as f:
        for i,line in enumerate(f,1):
            line=line.strip()
            m = re.match(r'^\$(argon2[^$]+)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$(.+)$', line)
            if m:
                alg, m_kb, t, p, rest = m.groups()
                rows.append([i, alg, int(m_kb), int(t), int(p), line])
            else:
                # try looser parse
                m2 = re.search(r'm=(\d+),t=(\d+),p=(\d+)', line)
                if m2:
                    rows.append([i, 'argon2', int(m2.group(1)), int(m2.group(2)), int(m2.group(3)), line])
                else:
                    rows.append([i, 'unknown', None, None, None, line])
with open(OUT,'w',newline='',encoding='utf-8') as out:
    import csv
    w=csv.writer(out)
    w.writerow(['index','type','memory_kb','time','parallelism','raw'])
    w.writerows(rows)
print("Wrote", OUT)
