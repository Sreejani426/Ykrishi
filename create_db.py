import sqlite3
 
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
 
# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT      
)
''')
 
cursor.execute('''
CREATE TABLE IF NOT EXISTS blog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    image_url TEXT,
    author TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')
 
cursor.execute('''
CREATE TABLE IF NOT EXISTS authorised_posters(
    username TEXT UNIQUE
)
''')
 
conn.commit()
conn.close()
 
print("Database, users , blog  and authorised_posters  tables are created successfully!")