"""Authentication microservice module with intentional SQL Injection vulnerability.

Used for autonomous remediation verification and demonstration testing.
"""

import sqlite3


class AuthService:
    """Mock authentication service connecting to in-memory SQLite."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Create users table and seed initial administrative record."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'SuperSecretPass123!', 'admin')"
        )
        self.conn.commit()

    def authenticate_user(self, username: str, password: str) -> dict[str, str] | None:
        """Authenticate user against database.

        VULNERABILITY: Direct string interpolation allows SQL injection bypass (CWE-89).
        Remediation: Use parameterized queries: cursor.execute(query, (username, password)).
        """
        cursor = self.conn.cursor()
        # Intentional vulnerability for security agent remediation demonstration
        query = (
            f"SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        cursor.execute(query)
        row = cursor.fetchone()

        if row:
            return {"id": str(row[0]), "username": row[1], "role": row[2]}
        return None
