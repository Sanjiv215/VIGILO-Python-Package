def query_user(cursor, username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
