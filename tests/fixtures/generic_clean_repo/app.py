"""Clean Python module (no findings expected)."""
import os
import sqlite3

DB_PATH = os.environ.get("DATABASE_URL", "app.db")


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def main():
    conn = sqlite3.connect(DB_PATH)
    print(get_user(conn, 1))


if __name__ == "__main__":
    main()
