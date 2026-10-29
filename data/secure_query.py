import sqlite3


def get_user(username: str) -> dict | None:
    """Return a user's public profile using a parameterized query."""
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row

        connection.execute(
            """
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )

        connection.executemany(
            "INSERT INTO users VALUES (?, ?, ?)",
            [
                ("darshan", "Darshan", "user"),
                ("admin", "Administrator", "admin"),
            ],
        )

        row = connection.execute(
            """
            SELECT username, display_name, role
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        return dict(row) if row else None
