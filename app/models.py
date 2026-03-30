# app/models.py
#
# FIX (Issue 1 — honey_index plaintext storage):
#   OLD: honey_index = db.Column(db.Integer, nullable=False)
#        Stored which slot held the real hash. Leaks the pool structure.
#   NEW: honey_index column REMOVED.
#        honey_salt = db.Column(db.String(32)) stores a random hex salt.
#        The real index is derived at login time via HMAC(password, salt).
#
# FIX (Issue 9 — username not unique):
#   OLD: username = db.Column(db.String(150), nullable=False)
#        No unique constraint — two users could share a username.
#   NEW: unique=True enforced at the ORM level.
#
# FIX (Issue 4 — in-memory lockout resets on restart):
#   OLD: login_attempts = {} dict in main.py
#   NEW: failed_attempts and locked_until columns on the User model.
#        Persisted in SQLite — survives server restarts.

from . import db
from datetime import datetime
import json


class User(db.Model):
    __tablename__ = "users"

    id         = db.Column(db.Integer, primary_key=True)

    # FIX: unique=True — no duplicate usernames
    username   = db.Column(db.String(150), nullable=False, unique=True, index=True)

    real_hash  = db.Column(db.String(500), nullable=False)

    # FIX: honey_index REMOVED — never store it.
    # honey_salt is a 32-char hex string (16 random bytes).
    # The real index is derived as: HMAC(password, honey_salt) % pool_size
    honey_salt = db.Column(db.String(32), nullable=False)

    honey_hashes = db.Column(db.Text, nullable=False, default='[]')

    cracked    = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # FIX: lockout state persisted to DB (Issue 4)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until    = db.Column(db.DateTime, nullable=True)

    # ── Honey pool helpers ────────────────────────────────────────────────────

    def set_honey_hashes(self, list_of_hashes: list[str]):
        self.honey_hashes = json.dumps(list_of_hashes)

    def get_honey_hashes(self) -> list[str]:
        return json.loads(self.honey_hashes)

    def pool_size(self) -> int:
        return len(self.get_honey_hashes())

    # ── Lockout helpers ───────────────────────────────────────────────────────

    def is_locked(self, now: datetime = None) -> bool:
        now = now or datetime.utcnow()
        return self.locked_until is not None and now < self.locked_until

    def seconds_until_unlock(self, now: datetime = None) -> int:
        now = now or datetime.utcnow()
        if self.locked_until and now < self.locked_until:
            return int((self.locked_until - now).total_seconds())
        return 0

    def reset_lockout(self):
        self.failed_attempts = 0
        self.locked_until    = None

    def __repr__(self):
        return f"<User {self.username!r} cracked={self.cracked}>"