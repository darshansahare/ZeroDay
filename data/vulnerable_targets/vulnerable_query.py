def run_query_vulnerable(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    cursor.execute("CREATE TABLE users (username TEXT, role TEXT)")
    cursor.executemany(
        "INSERT INTO users VALUES (?, ?)",
        [("darshan", "user"), ("admin", "admin")],
    )

    query = (
        f"SELECT username, role FROM users "
        f"WHERE username = '{username}'"
    )

    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result
