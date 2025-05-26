import sqlite3

# Replace 'database.db' with your actual DB filename
conn = sqlite3.connect('ykrishi.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS blog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    author TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()
conn.close()

print(" blogs table created successfully.")
