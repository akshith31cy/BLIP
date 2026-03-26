import sqlite3

def init_db():
    # Connect to SQLite database (creates the file if it doesn’t exist)
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Create the users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT,
                    password_hash TEXT,
                    honey_data TEXT
                )''')

    # Save and close
    conn.commit()
    conn.close()

# Call the function here to actually create the table
init_db()
