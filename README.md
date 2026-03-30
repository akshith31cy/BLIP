# LEAP — Leakage-Resilient Password Storage

### Using Honey Encryption, Adversarial Hash Testing & Autonomous Security Agents

---

## What is LEAP?

LEAP is a cybersecurity research project that demonstrates how to make stolen password databases useless to attackers. It combines three independent defence layers:

1. **Honey Encryption** — Every user's password is stored as 1 real Argon2id hash hidden among 9 convincing decoy hashes. An attacker who steals the database cannot tell which hash is real.

2. **Adversarial Hash Testing** — The system automatically runs real dictionary attacks against its own stored hashes using John the Ripper, measuring actual crack resistance rather than estimating it.

3. **Autonomous Security Agents** — A pipeline of agents runs on every registration and login event, scores the current security posture, applies improvements automatically, and generates structured reports.

---

## The Core Problem This Solves

In every major credential breach (LinkedIn 2012, Adobe 2013, RockYou2021), attackers follow the same workflow:

```
Dump database → Identify hash format → Run GPU attack → Crack 30-60% of accounts in 48 hours
```

LEAP disrupts step 2. Even after dumping the database, an attacker sees 10 × N identical-looking Argon2id hashes for N users. There is no cryptographic way to identify which one is real without the correct password. Cracking any decoy gives a plausible-looking but wrong password.

---

## Empirical Results

These results are from real John the Ripper attacks run against exported hashes using RockYou wordlist slices:

| Algorithm | Wordlist Size | Attack Type | Crack Rate | Mean Time |
|---|---|---|---|---|
| bcrypt | 10,000 | wordlist | 0% | 96s |
| bcrypt | 50,000 | wordlist | 0% | 442s |
| bcrypt | 100,000 | wordlist | 0% | 882s |
| bcrypt | 200,000 | wordlist | 0% | 1766s |
| bcrypt | All sizes | wordlist+rules | 0% | 3601s (timeout) |
| Argon2id | All sizes | All types | 0% | — |

SHA-256 cracks at approximately **1,800,000 H/s**.
Argon2id cracks at approximately **12 H/s**.
That is a **150,000× difference** in attack resistance.

---

## Project Structure

```
leakage_resilient_password_storage/
│
├── app/                          Flask web application
│   ├── __init__.py               App factory + SQLAlchemy setup
│   ├── main.py                   Routes: register, login, export, APIs
│   ├── models.py                 User model (honey_salt, DB lockout)
│   ├── hash_algorithms.py        Argon2id hashing and verification
│   ├── honey_encryptor.py        Honey pool generation + HMAC index
│   ├── templates/
│   │   ├── index.html            Registration page
│   │   ├── login.html            Login page with honey pool visual
│   │   ├── dashboard.html        Security dashboard
│   │   └── thanks.html           Post-registration confirmation
│   └── static/
│       └── dashboard.js          Dashboard interactivity
│
├── agents/                       Autonomous security pipeline
│   ├── hash_testing_agent.py     Scores hash strength + runs JtR probe
│   ├── security_agent.py         Reads reports + applies improvements
│   └── report_generator.py       Merges results into structured reports
│
├── adversarial_hash_testing/     Attack simulation module
│   ├── hash_algorithms.py        Hash + verify functions (correct API)
│   └── attack_simulation.py      Dictionary attack simulator
│
├── honey_encryption/             Research/demo honey encryption module
│   └── honey_encryptor.py        HMAC-based honey encrypt/decrypt
│
├── tests/                        Testing and benchmarking
│   ├── john_runner.py            Full John the Ripper pipeline
│   ├── benchmark_pipeline.py     Hash generation + verification benchmarks
│   ├── hash_performance.py       Dataset benchmark runner
│   ├── run_attacks_tuned.py      JtR multi-slice attack runner
│   ├── plots/                    Generated performance graphs
│   ├── honey/                    Honey encryption analysis scripts
│   ├── analysis/                 Attack result CSVs and plots
│   └── john_logs/                JtR session logs
│
├── data/                         Common password wordlists (1k to 100k)
├── data_rockyou/                 RockYou slices (10k to 1M)
├── database/                     SQLite database
│   └── users.db                  Auto-created on first run
├── reports/                      Agent-generated JSON reports
└── requirements.txt
```

---

## Security Architecture

### Honey Pool (HMAC-based index derivation)

The real password's position in the pool is **never stored**. It is derived at login time using:

```python
index = HMAC(password, honey_salt, SHA256) % pool_size
```

Only the `honey_salt` (a random 16-byte value) is stored in the database. Without the correct password, the index cannot be computed. An attacker with the full database still cannot identify the real hash.

### Argon2id Parameters

```
Algorithm:    Argon2id  (hybrid — resists both GPU and side-channel attacks)
Memory cost:  65536 KB  (64 MB per hash — expensive to parallelise on GPU)
Time cost:    2          (2 iterations)
Parallelism:  1
```

### Lockout Persistence

Failed login attempts and lockout expiry are stored in the database, not in memory. The lockout survives server restarts.

### Autonomous Agent Pipeline

```
Register / Login event
        ↓
Hash Testing Agent
  → detects algorithm
  → scores security 0-100
  → estimates crack time
  → runs JtR probe (if installed)
        ↓
Security Agent
  → reads report
  → upgrades algorithm if weak
  → increases memory/time cost if needed
  → expands honey pool if small
  → logs all changes
        ↓
Report Generator
  → merges results into JSON
  → appends to report index
  → exposes via Flask API
        ↓
Dashboard
  → displays live results
```

---

## Installation

### Prerequisites

- Python 3.11 or higher
- Git
- John the Ripper Jumbo (for adversarial testing — optional)

### Clone the repository

```bash
git clone https://github.com/akshith31cy/BLIP.git
cd BLIP
```

### Create and activate virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / Mac
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the application

```bash
python -m flask run
```

Open your browser and go to `http://127.0.0.1:5000`

---

## Running the Tests

### Attack simulation (verifies correct hash verification)

```bash
cd adversarial_hash_testing
python attack_simulation.py
```

Expected output shows SHA-256 cracking instantly, bcrypt and Argon2id taking seconds per attempt — demonstrating the H/s difference.

### Hash benchmark pipeline

```bash
python tests/benchmark_pipeline.py --sizes 1000 5000 --algorithms sha256 bcrypt argon2id
```

Results saved to `tests/benchmark_results.csv`.

### John the Ripper adversarial pipeline

First install John Jumbo (Linux / WSL):

```bash
sudo apt install git build-essential libssl-dev -y
git clone https://github.com/openwall/john -b bleeding-jumbo john-jumbo
cd john-jumbo/src && ./configure && make -sj4
export PATH="$HOME/john-jumbo/run:$PATH"
```

Then export hashes and run the attack:

```bash
# Export hashes (visit in browser or run Flask first)
http://127.0.0.1:5000/export

# Run full JtR pipeline
python tests/john_runner.py --format argon2id --wordlist data/sample_10000.txt --max-time 60
```

Results saved to `tests/john_results/`.

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Registration page |
| `/login` | GET, POST | Login page and authentication |
| `/dashboard` | GET | Security dashboard |
| `/export` | GET | Export honey hashes for JtR |
| `/api/user_stats` | GET | User counts and honey pool stats |
| `/api/reports/latest` | GET | Latest security agent report |
| `/api/reports/history` | GET | All report history |
| `/api/reports/summary` | GET | Aggregate stats for dashboard |
| `/api/security/changes` | GET | Recent auto-applied improvements |
| `/api/security/config` | GET | Current live security configuration |

---

## Dashboard

The dashboard shows live data pulled from the agent report system:

- **Security score ring** — 0 to 100 score based on algorithm, parameters, and pool size
- **KPI cards** — total users, active, compromised, honey entries, reports run, auto-fixes applied
- **Honey pool visualisation** — all 10 slots displayed equally (real slot unknown — by design)
- **Attack resistance panel** — H/s comparison between SHA-256, bcrypt, Argon2id
- **Agent recommendations** — prioritised list of improvements detected
- **Security changes** — log of all auto-applied improvements
- **Report history** — table of every agent scan with level, score, and timestamp

---

## Key Security Fixes (v2)

These issues were identified and fixed in the current version:

| Issue | Fix |
|---|---|
| `honey_index` stored in plaintext | Removed entirely — HMAC derivation at login |
| Mutation-based decoys leak real password structure | Replaced with independent wordlist sampling |
| Argon2/bcrypt attack simulation used `==` comparison | Fixed to use `ph.verify()` and `bcrypt.checkpw()` |
| In-memory lockout resets on restart | Moved to `failed_attempts` / `locked_until` DB columns |
| Argon2i used instead of Argon2id | Explicit `type=argon2.Type.ID` |
| Username not unique in database | `unique=True` constraint enforced |
| `honey_index` returned in login JSON response | Removed from all API responses |

---

## Research Foundation

This project is based on the honey encryption concept introduced by:

> Juels, A., & Ristenpart, T. (2014). Honey Encryption: Security Beyond the Brute-Force Bound. *Advances in Cryptology — EUROCRYPT 2014.*

The adversarial testing methodology uses John the Ripper Jumbo with the RockYou password corpus, following established password security benchmarking practices.

Hash algorithm recommendations follow:
- NIST SP 800-63B (Digital Identity Guidelines)
- OWASP Password Storage Cheat Sheet (2024)

---

## Tech Stack

| Component | Technology |
|---|---|
| Web framework | Flask 2.3.2 |
| Database ORM | SQLAlchemy 2.0 + SQLite |
| Password hashing | argon2-cffi (Argon2id) |
| Adversarial testing | John the Ripper Jumbo |
| Decoy generation | RockYou wordlist sampling |
| Frontend | HTML + CSS + Chart.js |
| Benchmarking | psutil + Python time module |
| Report storage | JSON + JSONL flat files |

---

## Author

**Akshith** — Final Year Cybersecurity Research Project

---

## License

This project is for academic and research purposes.
