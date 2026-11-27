def f(cursor, user):
    q = "SELECT * FROM t WHERE n='"
    # ruleid: sql-injection-string-concat
    cursor.execute("SELECT * FROM t WHERE n='" + user + "'")
    # ruleid: sql-injection-string-concat
    cursor.execute(q + user)
    # ruleid: sql-injection-string-concat
    cursor.executemany("INSERT INTO t VALUES (" + user + ")", [])
    # ok: sql-injection-string-concat
    cursor.execute("SELECT * FROM t WHERE n=%s", (user,))
    # ok: sql-injection-string-concat
    cursor.execute("SELECT * FROM t " + "WHERE 1=1")
