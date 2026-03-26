# app/models.py
from . import db
from datetime import datetime
import json

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    real_hash = db.Column(db.String(500), nullable=False)   # argon2 hash of real password
    honey_index = db.Column(db.Integer, nullable=False)     # which index in the honey list is real
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # store honey list as JSON array of hashes (length = honey_count)
    honey_hashes = db.Column(db.Text, nullable=False, default='[]')

    cracked = db.Column(db.Boolean, default=False)  # mark if cracked after adversarial test

    def set_honey_hashes(self, list_of_hashes):
        self.honey_hashes = json.dumps(list_of_hashes)

    def get_honey_hashes(self):
        import json
        return json.loads(self.honey_hashes)
