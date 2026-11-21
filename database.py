
import sqlite3

connection_obj = sqlite3.connect(
    "vault.db",
    check_same_thread=False
)

# Enable foreign key enforcement
connection_obj.execute("PRAGMA foreign_keys = ON")

cursor_obj = connection_obj.cursor()

# Create users table
table_user = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
"""

# Create credential table
table_creation_query = """
CREATE TABLE IF NOT EXISTS credential (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service VARCHAR(255) NOT NULL,
    username CHAR(25) NOT NULL,
    password CHAR(25) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

cursor_obj.execute(table_user)
cursor_obj.execute(table_creation_query)

connection_obj.commit()

print("Database is Ready!")

def add_credential(user_id, service, username, password):
    user_to_add = (user_id, service, username, password)

    cursor_obj.execute(
        """
        INSERT INTO credential
        (user_id, service, username, password)
        VALUES (?, ?, ?, ?)
        """,
        user_to_add
    )

    connection_obj.commit()

def get_credentials(user_id=None):
    if user_id is None:
        cursor = connection_obj.execute("SELECT * FROM credential")
    else:
        cursor = connection_obj.execute(
            "SELECT * FROM credential WHERE user_id = ?",
            (user_id,),
        )
    
    data = cursor.fetchall()
    return data

def delete_credential(id, user_id=None):
    if user_id is None:
        cursor_obj.execute(
            "DELETE FROM credential WHERE id = ?",
            (id,),
        )
    else:
        cursor_obj.execute(
            "DELETE FROM credential WHERE id = ? AND user_id = ?",
            (id, user_id),
        )
    connection_obj.commit()
    return cursor_obj.rowcount

def update_credential(credential_id, service, username, password, user_id=None):
    if user_id is None:
        cursor_obj.execute(
            "UPDATE credential SET service = ?, username = ?, password = ? WHERE id = ?",
            (service, username, password, credential_id),
        )
    else:
        cursor_obj.execute(
            "UPDATE credential SET service = ?, username = ?, password = ? "
            "WHERE id = ? AND user_id = ?",
            (service, username, password, credential_id, user_id),
        )
    connection_obj.commit()
    return cursor_obj.rowcount

def register_user(username, email, hashed_password):
    cursor_obj.execute(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        (username, email, hashed_password)
    )

    connection_obj.commit()
    return cursor_obj.lastrowid

def get_user_by_email(email):
    cursor_obj.execute(
        """
        SELECT id, username, email, password_hash
        FROM users
        WHERE email = ?
        """,
        (email,)
    )

    return cursor_obj.fetchone()

# Select data
# cursor_obj = connection_obj.execute(
#     '''SELECT * FROM credential'''
# )

# data = cursor_obj.fetchall()

# Close the connection to the database
# connection_obj.close()
