import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Fetch all tables in the database
c.execute("SELECT name FROM sqlite_master WHERE type='table';")

# Print the list of tables
print("Tables in users.db:", c.fetchall())

conn.close()
