import sqlite3

conn = sqlite3.connect("vault.db")
conn.execute("PRAGMA foreign_keys = ON")

cursor = conn.cursor()

cursor.execute(
    "DELETE FROM users WHERE id = ?",
    (1,)
)

conn.commit()

print("Dummy user deleted!")